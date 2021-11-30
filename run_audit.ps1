[CmdletBinding()]
param (
      [string] $group,
      [string] $outfile
)


# Set Variables for Audit
$BENCHMARK = "CIS"
$AUDIT_BIN = "C:\vagrant\goss.exe"
$AUDIT_FILE = "goss.yml"
$AUDIT_VARS = "vars\$BENCHMARK.yml"
$AUDIT_CONTENT_LOCATION = "C:\vagrant"
$AUDIT_CONTENT_VERSION = "Win2019-$BENCHMARK-Audit"
$AUDIT_CONTENT_DIR = "$AUDIT_CONTENT_LOCATION\$AUDIT_CONTENT_VERSION"

# Allow Alpha version to run
$env:GOSS_USE_ALPHA=1

<# 
Determine Server type -e.g. standalone, domain member , PDC etc
 2 StandAlone Server
 3 Member Server
 4 Backup Domain Controller
 5 Primary Domain Controller
#>
$serverrole = (wmic.exe ComputerSystem get DomainRole | Select-String -Pattern "[0-9]")
$servertype = ($servertype) -replace '\D+(\d+)','$1'

# Epoch time is required (as per Unix based from UTC)
$AUDIT_TIME = ([Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s")))

# $group - ability to add a group to the metadata to compare same group server results
if ([string]::IsNullOrEmpty($group)){
    $auto_group = "ungrouped"
    }
else {
    $auto_group = "$group"
    }


# Run Required commands based upon server type to capture system information to be audited

if ( $servertype = 2 )
{
  $OS_TYPE="StandAlone Server"
  powershell.exe -noninteractive -noprofile -command secedit.exe /export /cfg $AUDIT_CONTENT_LOCATION\secedit_$AUDIT_TIME.txt
  auditpol.exe /get /category:* > $AUDIT_CONTENT_LOCATION\auditpol_$AUDIT_TIME.txt
}
else 
{
      if ( $servertype = 3 )
       {
        $OS_TYPE="Member Server"
       }
      elif ( $servertype = 4 )
       {
        $OS_TYPE="Primary Domain Controller"
       }
      elif ( $servertype = 5 )
       {
        $OS_TYPE="Backup Domain Controller"
       }
      else {
        $OS_TYPE="Workstation"
       }
  powershell.exe -noninteractive -noprofile -command gpresult /v /r $AUDIT_CONTENT_LOCATION\gpresult_$AUDIT_TIME.txt
  auditpol.exe /get /category:* > $AUDIT_CONTENT_LOCATION\auditpol_$AUDIT_TIME.txt
}


# get metadata
$os_name="Windows_2019_server"
$machine_uuid=(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
$epoch=$AUDIT_TIME
$TZ=(Get-TimeZone).Id
$os_locale=$TZ -replace ' ','_'
$os_version=(([System.Environment]::OSVersion.Version).build)
$os_hostname=(hostname)
$audit_run="wrapper"

# Output files
$gpresult_file="$AUDIT_CONTENT_LOCATION\gpresult_$AUDIT_TIME.txt"
$auditresult_file="$AUDIT_CONTENT_LOCATION\auditpol_$AUDIT_TIME.txt"
$secedit_file="$AUDIT_CONTENT_LOCATION\secedit_$AUDIT_TIME.txt"


# Probably the ugliest thing ever with so much room to go wrong :)


$AUDIT_JSON_VARS = "{ 'machine_uuid': `'$machine_uuid`', 'epoch': `'$epoch`', 'audit_run': `'wrapper`', 'os_locale': `'$os_locale'`, 'os_release': `'$os_version`', 'windows2019cis_os_distribution': `'$os_name`', 'os_hostname': `'$os_hostname`', 'auto_group': `'$auto_group`', 'gpresult_file': `'$AUDIT_CONTENT_LOCATION\gpresult_$AUDIT_TIME.txt`', 'auditresult_file': `'$AUDIT_CONTENT_LOCATION\auditpol_$AUDIT_TIME.txt`', 'secedit_file': `'$AUDIT_CONTENT_LOCATION\secedit_$AUDIT_TIME.txt`'}"


# Set up AUDIT_OUT
#$outfile
if ([string]::IsNullOrEmpty($outfile)){
    $AUDIT_OUT = "$AUDIT_CONTENT_LOCATION\audit_$os_hostname_$epoch.json"
    }
else {
    $AUDIT_OUT = "$outfile"
    }

$AUDIT_ERR = "$AUDIT_CONTENT_LOCATION\audit_$os_hostname_$epoch.err"

# create empty file
New-Item -ItemType file $AUDIT_OUT
New-Item -ItemType file $AUDIT_ERR


# run audit
# appears when parent job exits before children - the goss run is typical of this behaviour
# the way its tracked does not work as expected https://github.com/PowerShell/PowerShell/issues/15555


$AUDIT_PARAMS="`"--g $AUDIT_CONTENT_DIR\$AUDIT_FILE --vars $AUDIT_CONTENT_DIR\$AUDIT_VARS  --vars-inline `"$AUDIT_JSON_VARS`" v --format json --format-options pretty`""

#Start-Process -NoNewWindow -Wait  -FilePath $AUDIT_BIN -ArgumentList $AUDIT_PARAMS

# The following is the output of the run_audit variable and owkrs as expected when run manually
# C:\vagrant\goss.exe --gossfile C:\vagrant\Win2019-CIS-Audit\goss.yml --vars C:\vagrant\Win2019-CIS-Audit\vars\CIS.yml --vars-inline "{ 'machine_uuid': '1D63E47F-C00E-48C2-8093-1C84645C18F7', 'epoch': '1637835028', 'audit_run': 'wrapper', 'os_release': '17763', 'windows2019cis_os_distribution': 'Windows_2019_server', 'os_hostname': 'win2019mem', 'auto_group': 'ungrouped', 'gpresult_file': 'C:\vagrant\gpresult_1637835028.txt', 'auditresult_file': 'C:\vagrant\auditpol_1637835028.txt', 'secedit_file': 'C:\vagrant\secedit_1637835028.txt'}" v --format json --format-options pretty | Format-Table -Autosize | Out-File C:\vagrant\audit_1637835028.json

# run audit 2
#$run_audit = @"
#$AUDIT_BIN --gossfile $AUDIT_CONTENT_DIR\$AUDIT_FILE --vars $AUDIT_CONTENT_DIR\$AUDIT_VARS --vars-inline `"$AUDIT_JSON_VARS`" v --format json --format-options pretty | Format-Table -Autosize | Out-File $AUDIT_OUT
#"@
#$run_audit

# The following is the output of the run_audit variable and works when run manually
# C:\vagrant\goss.exe --gossfile C:\vagrant\Win2019-CIS-Audit\goss.yml --vars C:\vagrant\Win2019-CIS-Audit\vars\CIS.yml --vars-inline "{ 'machine_uuid': '1D63E47F-C00E-48C2-8093-1C84645C18F7', 'epoch': '1637835028', 'audit_run': 'wrapper', 'os_release': '17763', 'windows2019cis_os_distribution': 'Windows_2019_server', 'os_hostname': 'win2019mem', 'auto_group': 'ungrouped', 'gpresult_file': 'C:\vagrant\gpresult_1637835028.txt', 'auditresult_file': 'C:\vagrant\auditpol_1637835028.txt', 'secedit_file': 'C:\vagrant\secedit_1637835028.txt'}" v --format json --format-options pretty | Format-Table -Autosize | Out-File C:\vagrant\audit_1637835028.json

# Run audit 3
#$run_audit = "C:\vagrant\goss.exe --gossfile C:\vagrant\Win2019-CIS-Audit\goss.yml --vars C:\vagrant\Win2019-CIS-Audit\vars\CIS.yml --vars-inline `"{ 'machine_uuid': '1D63E47F-C00E-48C2-8093-1C84645C18F7', 'epoch': '1637834060', 'audit_run': 'wrapper', 'os_release': '17763', 'windows2019cis_os_distribution': 'Windows_2019_server', 'os_hostname': 'win2019mem', 'auto_group': 'ungrouped', 'gpresult_file': 'C:\vagrant\gpresult_1637834060.txt', 'auditresult_file': 'C:\vagrant\auditpol_1637834060.txt', 'secedit_file': 'C:\vagrant\secedit_1637834060.txt'}`" v --format json --format-options pretty | Format-Table -Autosize | Out-File $AUDIT_OUT"
#$run_audit

# The following works when run alone and is the output of the run_audit variable number 3
# C:\vagrant\goss.exe --gossfile C:\vagrant\Win2019-CIS-Audit\goss.yml --vars C:\vagrant\Win2019-CIS-Audit\vars\CIS.yml --vars-inline "{ 'machine_uuid': '1D63E47F-C00E-48C2-8093-1C84645C18F7', 'epoch': '1637834060', 'audit_run': 'wrapper', 'os_release': '17763', 'windows2019cis_os_distribution': 'Windows_2019_server', 'os_hostname': 'win2019mem', 'auto_group': 'ungrouped', 'gpresult_file': 'C:\vagrant\gpresult_1637834060.txt', 'auditresult_file': 'C:\vagrant\auditpol_1637834060.txt', 'secedit_file': 'C:\vagrant\secedit_1637834060.txt'}" v --format json --format-options pretty | Format-Table -Autosize | Out-File C:\vagrant\audit_1637834559.json


# Run audit 4
#$job =  { Start-Process -NoNewWindow -Passthru -Wait -FilePath "$AUDIT_BIN" -ArgumentList "$AUDIT_PARAMS" -RedirectStandardOutput "$AUDIT_OUT" -RedirectStandardError error >> "$AUDIT_OUT"  }
#Invoke-Command -ScriptBlock $job


# This runs the job, waits for its children to complete and outputs to file
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = "$AUDIT_BIN"
$pinfo.RedirectStandardError = $true
$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.Arguments = "--gossfile $AUDIT_CONTENT_DIR\$AUDIT_FILE --vars $AUDIT_CONTENT_DIR\$AUDIT_VARS  --vars-inline `"$AUDIT_JSON_VARS`" v --format json --format-options pretty"
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null
$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()
$p.WaitForExit()

# Write to relevant output to file
Write-Output "$stdout" | Out-File -FilePath "$AUDIT_OUT"
Write-Output "$stderr" | Out-File -FilePath "$AUDIT_ERR"


#Write-Host "exit code: " + $p.ExitCode


# Summary of Output

if ( Select-String $BENCHMARK $AUDIT_OUT )
    { 
       $audit_summary=Get-Content "$AUDIT_OUT" -tail 8
       write-host "Audit Successful`n"
       write-host "$audit_summary"
       write-host "`nComplete audit file can be found at $AUDIT_OUT"
    }
else
    {
        Write-Host "Fail Audit - There were issues when running the audit please investigate $AUDIT_OUT" 
    }
