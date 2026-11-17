#Requires -Version 5.1
<#
.SYNOPSIS
    Run the CIS Windows Server 2019 audit with syver.

.DESCRIPTION
    The PowerShell counterpart of run_audit.sh, with one addition.

    Most of what this benchmark checks is not readable by a goss resource:
    account policy, user rights, audit policy and per-user hives all come from
    secedit / auditpol / the registry under HKEY_USERS. Giving each control its
    own shell-out would mean roughly 130 secedit exports of the same data,
    contending on LSA and intermittently reading a half-written file.

    So this script collects once, normalises the result, and writes a snapshot
    that the audit matches against with plain file: checks. What to collect
    comes from collector_targets.json, which the generator writes alongside the
    specs, so the set of things collected and the set of things asserted cannot
    drift apart.

    The snapshot is a policy export in the temp directory. That does mean the
    audit writes a file; the alternative is 130 concurrent exports.

.NOTES
    syver on Windows is alpha and refuses to run without --use-alpha=1.
    A check syver cannot run ERRORS rather than passing, which is the behaviour
    the whole audit relies on. See syver_for_windows.md.
#>
[CmdletBinding()]
param(
    [ValidateSet('json', 'documentation', 'rspecish', 'junit', 'tap', 'nagios', 'silent')]
    [string]$Format = 'json',

    [string]$Group = 'ungrouped',

    [int]$MaxConcurrent = 50,

    [string]$OutFile,

    [string]$VarsPath,

    [ValidateSet('Workstation', 'Server')]
    [string]$SystemType = 'Server',

    # Collect the policy snapshot and stop. Use this to eyeball the snapshot
    # before trusting a run.
    [switch]$CollectOnly,

    # Reuse an existing snapshot. The only way to read stale state, and it has
    # to be asked for.
    [switch]$SkipCollect
)

$ErrorActionPreference = 'Stop'

# Stop is right for the script's own logic, but wrong around a native command
# captured with 2>&1: PowerShell turns any stderr write into a terminating
# NativeCommandError, so a single syver warning would abort the run. Invoke-Syver
# relaxes it for exactly the length of the call and puts it back afterwards.
function Invoke-Syver {
    param([scriptblock]$Call)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try   { & $Call }
    finally { $ErrorActionPreference = $previous }
}

# Benchmark identity. Changes only on a new benchmark release.
$Benchmark    = 'CIS'
$BenchmarkVer = '4.0.0'
$BenchmarkOs  = 'Windows-2019'

# Overridable from the environment, mirroring run_audit.sh
$AuditBin = if ($env:AUDIT_BIN) { $env:AUDIT_BIN } else { 'C:\Program Files\syver\syver.exe' }
# Minimum, and enforced rather than warned about. From 0.11.0 syver reports a
# check it cannot run as an ERROR instead of letting it pass quietly; below that
# an unsupported assertion looks like a pass, which is the vacuous green run this
# audit exists to avoid. 0.11.1 is the version the content was validated against
# and the earliest release carrying that behaviour, so anything older is refused
# rather than noted.
$AuditBinMinVer = '0.11.1'
$AuditFile = if ($env:AUDIT_FILE) { $env:AUDIT_FILE } else { 'goss.yml' }
$AuditContentLocation = if ($env:AUDIT_CONTENT_LOCATION) {
    $env:AUDIT_CONTENT_LOCATION
} else {
    $env:ProgramData
}

$auditContentDir = Join-Path $AuditContentLocation "$BenchmarkOs-$Benchmark-Audit"
$gossFile        = Join-Path $auditContentDir $AuditFile
$targetsFile     = Join-Path $auditContentDir 'collector_targets.json'
$varfilePath     = if ($VarsPath) { $VarsPath } else { Join-Path $auditContentDir "vars\$Benchmark.yml" }
$snapshotPath    = Join-Path $env:SystemRoot 'Temp\win19cis_policy_snapshot.txt'
$snapshotDir     = Join-Path $env:SystemRoot 'Temp\win19cis_snapshot'

# Host role, derived once and used by both the collector and the audit vars.
$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
$systemRole = if ($domainRole -ge 4) { 'domaincontroller' }
              elseif ($domainRole -eq 3) { 'memberserver' }
              else { 'standalone' }

# Machine-relative SIDs. RID: tokens in collector_targets.json expand against
# this; the LocalAccount filter is load-bearing, because the unfiltered query
# hangs for minutes on a domain-joined host.
function Normalize-AuditGuid {
    <#  auditpol prints {0CCE9211-...}; the role writes {0cce9211-...}. Compare
        on a single normalised form so case and braces cannot cause a miss.  #>
    param([string]$Value)
    if (-not $Value) { return '' }
    return $Value.Trim().Trim('{', '}').ToLowerInvariant()
}


function Get-MachineSid {
    <#  On a domain controller there is no local SAM - the "local" account
        database IS the domain - so an unfiltered Win32_UserAccount query
        enumerates every domain account and can take minutes on a large domain;
        Select-Object -First 1 does not short-circuit the WMI enumeration.
        Get-LocalUser is not an alternative there either: the LocalAccounts
        module refuses to load on a DC. Branch instead.  #>
    param([string]$Role)

    if ($Role -eq 'domaincontroller') {
        # Domain Admins is RID 512 and always exists: one translate, no enumeration.
        try {
            $acct = New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN\Domain Admins")
            $sid  = $acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
            return ($sid -replace '-\d+$', '')
        } catch {
            return $null
        }
    }

    # Constrain the filter so the WMI provider does the work, not the pipeline.
    $sid = Get-CimInstance Win32_UserAccount `
        -Filter "LocalAccount=True AND SID LIKE 'S-1-5-21-%-500'" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty SID
    if (-not $sid) { return $null }
    return ($sid -replace '-\d+$', '')
}

function Resolve-Principal {
    param([string]$Value, [string]$MachineSid)

    $text = $Value.Trim().TrimStart('*')
    if ($text -like 'S-1-*') { return $text }
    if ($text -like 'RID:*' -and $MachineSid) { return "$MachineSid-$($text.Substring(4))" }
    try {
        return (New-Object System.Security.Principal.NTAccount($text)).Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        # An orphaned SID or a deleted account. Reporting it verbatim keeps this a
        # finding rather than an error.
        return "UNRESOLVED=$text"
    }
}

function New-PolicySnapshot {
    param([string]$Path, [string]$Directory, [string]$TargetsFile)

    if (-not (Test-Path -LiteralPath $TargetsFile)) {
        throw "collector_targets.json not found at $TargetsFile"
    }
    $targets = Get-Content -LiteralPath $TargetsFile -Raw | ConvertFrom-Json
    $machineSid = Get-MachineSid -Role $systemRole
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("Snapshot.Epoch=$([int][double]::Parse((Get-Date -UFormat %s)))")
    # Appended per area as each one completes, not written up front as a
    # constant. A constant makes the canary prove only that the collector ran;
    # built incrementally it proves each area actually produced data, so a
    # partial collection fails loudly instead of leaving ~45 controls reading
    # ABSENT. The generated canary asserts the full expected list.
    $areasDone = New-Object System.Collections.Generic.List[string]

    # ---- secedit: System Access and Privilege Rights, in one export ----
    # The .inf is UTF-16LE with a BOM. Get-Content follows the BOM, so the
    # encoding is handled once here rather than in every check.
    # The target must NOT already exist. Over an existing file that is not a
    # UTF-16 export, secedit drops the [Unicode] header, writes single-byte text
    # and leaves in place any section it does not export - and still exits 0.
    # Host-proven on Server 2019. $PID keeps the name unique; the remove is belt
    # and braces.
    $inf = Join-Path $env:TEMP "win19cis_secedit_$PID.inf"
    if (Test-Path -LiteralPath $inf) { Remove-Item -LiteralPath $inf -Force }
    & secedit /export /areas SECURITYPOLICY USER_RIGHTS /cfg $inf /quiet | Out-Null
    $seceditRc = $LASTEXITCODE
    $policy = @{}
    if (Test-Path -LiteralPath $inf) {
        foreach ($line in Get-Content -LiteralPath $inf) {
            if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$') {
                $policy[$Matches[1]] = $Matches[2].Trim().Trim('"')
            }
        }
        Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue
    }
    # A failed or empty export would make every SystemAccess.* read ABSENT and
    # every PrivilegeRights.* read NONE - roughly 45 controls failing at once,
    # which looks like a catastrophically non-compliant host rather than a
    # collector that could not read. LSA contention shortly after a DC reboot or
    # during replication makes this materially more likely on a domain
    # controller, so it throws instead of writing a fabricated snapshot.
    if ($seceditRc -ne 0 -or $policy.Count -eq 0) {
        throw ("secedit export failed (exit $seceditRc, $($policy.Count) keys parsed). " +
               'Refusing to write a snapshot that would fail every policy control.')
    }

    foreach ($key in $targets.system_access) {
        if ($policy.ContainsKey($key)) {
            $lines.Add("SystemAccess.$key=$($policy[$key])")
        } else {
            $lines.Add("SystemAccess.$key=ABSENT")
        }
    }

    # A line is written for every right the benchmark covers, so "no one holds
    # it" and "the key is not in the export" both read as an empty value. That
    # removes the absent-versus-empty branch from every No One control.
    foreach ($right in $targets.privilege_rights) {
        $members = @()
        if ($policy.ContainsKey($right) -and $policy[$right]) {
            $members = @($policy[$right].Split(',') |
                Where-Object { $_.Trim() -ne '' } |
                ForEach-Object { Resolve-Principal -Value $_ -MachineSid $machineSid } |
                Sort-Object -Unique)
        }
        # An explicit NONE, never an empty value. goss splits a file into lines
        # and an empty file has none, so a /^$/ matcher can never match: every
        # "No One" control would fail while the host was actually compliant.
        if ($members.Count -eq 0) {
            $lines.Add("PrivilegeRights.$right=NONE")
        } else {
            $lines.Add("PrivilegeRights.$right=$($members -join ',')")
        }
    }

    $areasDone.Add('SECURITYPOLICY'); $areasDone.Add('USER_RIGHTS')

    # ---- auditpol: one call covering every subcategory ----
    # /r gives: Machine Name,Policy Target,Subcategory,Subcategory GUID,
    #           Inclusion Setting,Exclusion Setting
    # The inclusion setting is text, not a number, and both it and the
    # subcategory name are localised. The collector turns the text into the
    # numeric CIS talks in, so the 27 spec files stay locale-independent, and
    # records the GUID beside it so a localised host can be pinned by GUID later.
    # An unrecognised setting is recorded verbatim, which fails loudly rather
    # than passing on an unread value.
    $inclusionToValue = @{
        'No Auditing'         = 0
        'Success'             = 1
        'Failure'             = 2
        'Success and Failure' = 3
    }
    $auditByName = @{}
    $guidByName = @{}
    # The CIS Server 2019 role calls auditpol by subcategory GUID, not by name,
    # so collector_targets.json holds GUIDs. Keying only by name would miss all
    # 34 section 17 targets and record every one as ABSENT - a mass false
    # failure that reads like a catastrophically non-compliant host. auditpol
    # emits the GUID upper-case and the role writes it lower-case, so the key is
    # normalised rather than compared verbatim.
    $auditByGuid = @{}
    foreach ($row in @(& auditpol /get /category:* /r 2>$null)) {
        if ([string]::IsNullOrWhiteSpace($row)) { continue }
        $fields = $row.Split(',')
        if ($fields.Count -lt 5) { continue }
        $name = $fields[2].Trim()
        if ($name -eq 'Subcategory') { continue }
        $inclusion = $fields[4].Trim()
        $guid = $fields[3].Trim()
        $guidByName[$name] = $guid
        if ($inclusionToValue.ContainsKey($inclusion)) {
            $value = $inclusionToValue[$inclusion]
        } else {
            $value = "UNKNOWN=$inclusion"
        }
        $auditByName[$name] = $value
        $auditByGuid[(Normalize-AuditGuid $guid)] = $value
    }
    foreach ($target in $targets.auditpol) {
        # GUID first, because this benchmark's targets are GUIDs and the GUID
        # is locale-independent; fall back to the name for a benchmark that
        # still uses names.
        $guidKey = Normalize-AuditGuid $target.subcategory
        if ($auditByGuid.ContainsKey($guidKey)) {
            $lines.Add("AuditPolicy.$($target.rule)=$($auditByGuid[$guidKey])")
            $lines.Add("AuditPolicyGuid.$($target.rule)=$($target.subcategory)")
        } elseif ($auditByName.ContainsKey($target.subcategory)) {
            $lines.Add("AuditPolicy.$($target.rule)=$($auditByName[$target.subcategory])")
            $lines.Add("AuditPolicyGuid.$($target.rule)=$($guidByName[$target.subcategory])")
        } else {
            $lines.Add("AuditPolicy.$($target.rule)=ABSENT")
        }
    }

    $areasDone.Add('AUDITPOL')

    # ---- services ----
    # StartType is a .NET enum, so this is locale-independent. NotInstalled is
    # recorded explicitly: every CIS section 5 title is "Disabled or Not
    # Installed", and syver's own service: resource errors on an absent service.
    $services = @{}
    foreach ($svc in Get-Service -ErrorAction SilentlyContinue) {
        $services[$svc.Name] = $svc.StartType.ToString()
    }
    foreach ($name in $targets.services) {
        if ($services.ContainsKey($name)) {
            $lines.Add("Service.$name=$($services[$name])")
        } else {
            $lines.Add("Service.$name=NotInstalled")
        }
    }

    $areasDone.Add('SERVICES')

    # ---- firewall: what is in force, not what policy was written ----
    # ActiveStore, not the default store. Without it a setting that arrives
    # through policy reads back as NotConfigured, which looks like a finding and
    # is not one.
    $profiles = @{}
    foreach ($fw in Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue) {
        $profiles[$fw.Name] = $fw
    }
    foreach ($target in $targets.firewall) {
        $value = 'ABSENT'
        if ($profiles.ContainsKey($target.profile)) {
            $value = $profiles[$target.profile].($target.property).ToString()
        }
        $lines.Add("Firewall.$($target.profile).$($target.property)=$value")
    }

    $areasDone.Add('FIREWALL')

    # ---- per-user policy under HKEY_USERS ----
    # The remediation role's prelim REG LOADs every profile; an audit must not,
    # because that changes the host. So only loaded hives are examined, and the
    # count is reported so a one-profile pass on a ten-user machine is visible.
    $sids = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } |
        Select-Object -ExpandProperty PSChildName)
    $lines.Add("Hive.LoadedProfiles=$($sids.Count)")

    foreach ($target in $targets.hku) {
        if ($sids.Count -eq 0) {
            $lines.Add("HKU.$($target.rule)=NONCOMPLIANT no_user_hives_loaded")
            continue
        }
        $bad = @()
        foreach ($sid in $sids) {
            $key = "Registry::HKEY_USERS\$sid\$($target.subpath)"
            $actual = (Get-ItemProperty -LiteralPath $key -Name $target.name -ErrorAction SilentlyContinue).($target.name)
            if ($null -eq $actual) {
                $bad += "$sid=absent"
            } elseif ("$actual" -ne "$($target.data)") {
                $bad += "$sid=$actual"
            }
        }
        if ($bad.Count -eq 0) {
            $lines.Add("HKU.$($target.rule)=COMPLIANT profiles=$($sids.Count)")
        } else {
            $lines.Add("HKU.$($target.rule)=NONCOMPLIANT $($bad -join ' ')")
        }
    }

    $areasDone.Add('HKU')
    $lines.Add("Snapshot.Areas=$($areasDone -join ',')")

    # UTF-8 without a BOM. PowerShell 5.1's Out-File -Encoding utf8 writes one,
    # and a BOM on the first line would stop the first check matching.
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($Path, $lines, $utf8)

    # The same values again, one small file per key. goss prints the WHOLE file
    # when a contents: matcher fails, so a single combined snapshot turns one
    # failed control into 170 lines of noise and a 54-failure run into something
    # nobody will read. A file per key means a failure shows just that value.
    # The combined file above stays, for reading by eye and for the canaries.
    if (Test-Path -LiteralPath $Directory) {
        Remove-Item -LiteralPath $Directory -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    foreach ($line in $lines) {
        $split = $line.IndexOf('=')
        if ($split -lt 1) { continue }
        $key = $line.Substring(0, $split)
        $value = $line.Substring($split + 1)
        [System.IO.File]::WriteAllText((Join-Path $Directory $key), $value, $utf8)
    }
    return $lines.Count
}

# --------------------------------------------------------------------------
# Pre-checks
# --------------------------------------------------------------------------

Write-Host ''
Write-Host '## Pre-Checks Start'
Write-Host ''
$failure = 0

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Script needs to run with Administrator privileges'
    exit 1
}
Write-Host 'OK - running elevated'

if (-not $CollectOnly) {
    if (Test-Path -LiteralPath $AuditBin) {
        Write-Host "OK - Audit binary $AuditBin is available"
        $versionRaw = (Invoke-Syver { & $AuditBin --version 2>&1 }) -join ' '
        if ($versionRaw -match 'v?(\d+\.\d+\.\d+)') {
            $installed = [version]$Matches[1]
            if ($installed -ge [version]$AuditBinMinVer) {
                Write-Host "OK - syver version is ok ($installed >= $AuditBinMinVer)"
            } else {
                Write-Host ("WARNING - syver installed = $installed, does not meet minimum of " +
                    "$AuditBinMinVer. Below 0.11.0 an unsupported check passes quietly instead " +
                    "of erroring, so a clean run would not mean the host is compliant.")
                $failure = 2
            }
        } else {
            Write-Host "WARNING - could not parse a syver version from '$versionRaw'"
            $failure = 2
        }
    } else {
        Write-Host "WARNING - The audit binary is not available at $AuditBin"
        $failure = 1
    }

    if (Test-Path -LiteralPath $gossFile) {
        Write-Host "OK - $gossFile is available"
    } else {
        Write-Host "WARNING - the $gossFile is not available"
        $failure = 3
    }

    if (Test-Path -LiteralPath $varfilePath) {
        Write-Host "OK - $varfilePath is available"
    } else {
        Write-Host "WARNING - the $varfilePath is not available"
        $failure = 4
    }
}

if ($failure -ne 0) {
    Write-Host '## Pre-checks failed please see output'
    exit 1
}
Write-Host ''
Write-Host '## Pre-checks Successful'
Write-Host ''

# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

if ($SkipCollect) {
    if (-not (Test-Path -LiteralPath $snapshotPath)) {
        Write-Host "Fail: -SkipCollect was given but no snapshot exists at $snapshotPath"
        exit 1
    }
    Write-Host "WARNING - reusing the existing snapshot at $snapshotPath. It may be stale."
} else {
    $count = New-PolicySnapshot -Path $snapshotPath -Directory $snapshotDir `
        -TargetsFile $targetsFile
    Write-Host "OK - policy snapshot written to $snapshotPath ($count values)"
    Write-Host "OK - per-key files written to $snapshotDir"
}

if ($CollectOnly) {
    Write-Host 'Collection complete. Nothing else run because -CollectOnly was given.'
    exit 0
}

# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

$hostMachineUuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID
$hostEpoch       = [string][int][double]::Parse((Get-Date -UFormat %s))
$hostOsLocale    = (Get-TimeZone).Id
$osInfo          = Get-CimInstance -ClassName Win32_OperatingSystem
$currentVersion  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$hostOsHostname  = $env:COMPUTERNAME

if (-not $OutFile) {
    $OutFile = Join-Path $AuditContentLocation "audit_$hostOsHostname-$Benchmark-${BenchmarkOs}_$hostEpoch.$Format"
}

$auditJsonVars = @{
    benchmark_type    = $Benchmark
    benchmark_os      = $BenchmarkOs
    benchmark_version = $BenchmarkVer
    machine_uuid      = $hostMachineUuid
    epoch             = $hostEpoch
    os_locale         = $hostOsLocale
    os_release        = $currentVersion.DisplayVersion
    os_build          = "$($osInfo.Version).$($currentVersion.UBR)"
    os_distribution   = $osInfo.Caption
    os_hostname       = $hostOsHostname
    auto_group        = $Group
    system_type       = $SystemType
    # Passed inline so the audit always reads the snapshot this run wrote, even
    # if vars/CIS.yml carries a different default.
    win19cis_policy_snapshot = $snapshotPath
    win19cis_snapshot_dir    = $snapshotDir
    # Detected, not declared. A CIS Server benchmark splits its profiles into
    # Domain Controller and Member Server - 31 controls are DC-only and 36
    # MS-only - and several assert DIFFERENT expected membership per profile,
    # so guessing wrong produces contradictory failures that look like host
    # defects. DomainRole: 0/1 standalone/member workstation, 2 standalone
    # server, 3 member server, 4 backup DC, 5 primary DC. CIS treats any server
    # that is not a DC as a Member Server, standalone included.
    win19cis_system_role     = $systemRole
} | ConvertTo-Json -Compress

$formatArgs = if ($Format -eq 'json') { @('-f', 'json', '-o', 'pretty') } else { @('-f', $Format) }

Write-Host '#############'
Write-Host 'Audit Started'
Write-Host '#############'
Write-Host ''

# --use-alpha=1 is a global flag and has to precede the v subcommand. Without it
# syver refuses to run on Windows at all.
#
# The metadata goes in as a second --vars file rather than through
# --vars-inline. The flag itself is fine -- syver_for_windows.md section 3
# records it working in both shells, in either flag position, and rejecting a
# malformed value at parse time. The problem is purely PowerShell argument
# handling: the inner double quotes are stripped unless backslash-escaped, and
# once escaped the argument is split on the spaces inside values like
# "Microsoft Windows 11 Enterprise". --vars takes multiple files with later ones
# overriding, so this sidesteps the shell entirely. SYVER_VARS_INLINE would work
# too; a file is easier to inspect when something looks wrong.
$metaVarsFile = Join-Path $env:TEMP 'win19cis_meta_vars.json'
[System.IO.File]::WriteAllText($metaVarsFile, $auditJsonVars,
    (New-Object System.Text.UTF8Encoding($false)))

try {
    $output = Invoke-Syver {
        & $AuditBin --use-alpha=1 -g $gossFile `
            --vars $varfilePath --vars $metaVarsFile `
            v --max-concurrent $MaxConcurrent @formatArgs 2>&1
    }
} finally {
    Remove-Item -LiteralPath $metaVarsFile -Force -ErrorAction SilentlyContinue
}

[System.IO.File]::WriteAllLines($OutFile, $output, (New-Object System.Text.UTF8Encoding($false)))

if ($Format -in 'json', 'rspecish') {
    $output | Select-String -Pattern 'Count:' -Context 0, 4
} elseif ($Format -eq 'documentation') {
    $output | Select-Object -Last 2
}

Write-Host "Completed file can be found at $OutFile"
Write-Host '###############'
Write-Host 'Audit Completed'
Write-Host '###############'
