# Initial Powershell script
# 04/03/2022 - Beta release - ukbolly mindpointgroup


<#
.SYNOPSIS
Wrapper script to run an audit

.DESCRIPTION
Wrapper script to run an audit on the system using goss.
This allows for bespoke variables to be set

.PARAMETER varsfile
default: $AUDIT_VARS
Ability to set a variable file defined with the settings to match your requirements

.PARAMETER group
default: none
Ability to set a group that the system belongs to
Can be used when matching similar system in that same group

.PARAMETER outfile
default: $AUDIT_CONTENT_LOCATION\audit_$host_os_hostname_$host_epoch.json
Ability to set an outfile to send the full audit output to
Requires path to be set


.EXAMPLE
./run_audit.ps1
./run_audit.ps1 -varsfile myvars.yml
./run_audit.ps1 -outfile path/to/audit/output.json
./run_audit.ps1 -group webserver

.NOTES


.LINK
https://github.com/ansible-lockdown/Windows-2019-CIS-Audit/blob/devel/Docs/Security_remediation_and_auditing.md

#>

param (
      [string]$varsfile,
      [string]$group,
      [string]$outfile
)


## Variables

# Benchmark variables
$BENCHMARK = "CIS"
$BENCHMARK_VER  = "1.2.1"
$BENCHMARK_OS   = "Windows 2019"

# Set Variables for Audit

$AUDIT_BIN = "C:\vagrant\goss.exe"
$AUDIT_CONTENT_LOCATION = "C:\vagrant"

# Unless you know what your doing probably dont need to change these.
$AUDIT_FILE = "goss.yml"  
$AUDIT_VARS = "$BENCHMARK.yml" # This can be changed using cli option
$AUDIT_CONTENT_VERSION = "Win2019-$BENCHMARK-Audit"
$AUDIT_CONTENT_DIR = "$AUDIT_CONTENT_LOCATION\$AUDIT_CONTENT_VERSION"

### Shouldnt need to change anything past this point apart from tidy up the code

#$varsfile
if ([string]::IsNullOrEmpty($varsfile)){
    $AUDIT_VARS = "$BENCHMARK.yml"
    }
else {
    $AUDIT_VARS = "$varsfile"
    }


# Check file exists

$files = @( "$AUDIT_BIN", "$AUDIT_CONTENT_DIR\$AUDIT_VARS","$AUDIT_CONTENT_DIR\$AUDIT_FILE" )

Write-host "Pre checks - Ensure files exist"
foreach ($file in $files) {
  try {
     if (Test-Path -Path $file){
         write-host "OK - ""$file"" exists" -ForeGroundColor green
     }
     else{
          $file_missing = 'true'
          throw
     }  
  }
  catch {
     Write-host "Fail - ""$file"" Not found" -ForegroundColor red
     
  }
}

if ($file_missing){
    Write-Warning "Please Ensure variables are set correctly"
    Exit
    }
else{
    Write-Host "OK - Files Exist" -ForegroundColor green
}

# Allow Alpha version to run
# Until 0.4 is official when not required.
$env:GOSS_USE_ALPHA=1
$env:GOSS_TIMEOUT=10


# Check content exists before continuing


<# 
Determine Server type -e.g. standalone, domain member , PDC etc
 2 StandAlone Server
 3 Member Server
 4 Backup Domain Controller
 5 Primary Domain Controller
#>
$serverrole = (wmic.exe ComputerSystem get DomainRole | Select-String -Pattern "[0-9]")
$servertype = ($serverrole) -replace '\D+(\d+)','$1'

# Epoch time is required (as per Unix based from UTC)
$host_audit_time = ([Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s")))

# Output files
$gpresult_file="$AUDIT_CONTENT_LOCATION\gpresult_$host_audit_time.txt"
$auditresult_file="$AUDIT_CONTENT_LOCATION\auditpol_$host_audit_time.txt"
$secedit_file="$AUDIT_CONTENT_LOCATION\secedit_$host_audit_time.txt"

# $group - ability to add a group to the metadata to compare same group server results
if ([string]::IsNullOrEmpty($group)){
    $auto_group = "ungrouped"
    }
else {
    $auto_group = "$group"
    }


# Run Required commands based upon server type to capture system information to be audited
# Run audit policies capture script - required for all types

$Error.Clear()

Write-Host "Running Audit commands"

$audit_cmd = Invoke-Command -Script { auditpol.exe /get /category:* > $auditresult_file } -ErrorAction SilentlyContinue

Try {
      "$audit_cmd" 
}
Catch {  
}

If ($LASTEXITCODE -ne "0"){
    Write-Host "Unable to run auditpol.exe command"
    exit
}
Else{
    Write-Host "OK - ran auditpol report - created $auditresult_file" -ForegroundColor green
    Write-Host ""
}



if ( $servertype = 2 )
{
  $OS_TYPE="StandAlone Server"
  Write-Host "$OS_TYPE system discovered running relevant checks"
  $secedit_cmd = Invoke-Command -Script {secedit.exe /export /quiet /cfg $secedit_file } -ErrorAction SilentlyContinue
  Try {
      "$secedit_cmd" 
  }
  Catch {
  }
  If ($LASTEXITCODE -ne "0"){
    Write-Host "Unable to run secedit.exe command"
    exit
  }
  Else{
      Write-Host "OK - secedit report - created $secedit_file" -ForegroundColor green
  }
}
Else 
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
  Write-Host "$OS_TYPE system discovered running relevant checks"
  powershell.exe -noninteractive -noprofile -command gpresult /v /r $gpresult_file

}

# get metadata
$host_os_name=((Get-CimInstance -ClassName CIM_OperatingSystem).Caption ) -replace ' ','_'
$host_machine_uuid=(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
$host_epoch=$host_audit_time
$host_os_locale=((Get-TimeZone).Id) -replace ' ','_'
$host_os_version=Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty Caption
$host_os_hostname=(hostname)
$host_system_type="$OS_TYPE"

# allow audit_run variable to be run from external script providing different vars
if ([string]::IsNullOrEmpty($audit_run)){
    $audit_run="wrapper"
}

# Set the audit_content dir assist in fault finding due to go and windows \ / path differences

$audit_content="$AUDIT_CONTENT_DIR"

# Probably the ugliest thing ever with so much room to go wrong :)
# Has to be a better way

$AUDIT_JSON_VARS = "{ 'benchmark_type': `'$BENCHMARK`', 'benchmark_version': `'$BENCHMARK_VER`', 'benchmark_os': `'$BENCHMARK_OS`', 'machine_uuid': `'$host_machine_uuid`','os_deployment_type': `'$host_system_type`', 'epoch': `'$host_epoch`', 'os_locale': `'$host_os_locale`', 'os_release': `'$host_os_version`', 'host_os_distribution': `'$host_os_name`', 'os_hostname': `'$host_os_hostname`', 'auto_group': `'$auto_group`', 'gpresult_file': `'$$gpresult_file`', 'auditresult_file': `'$auditresult_file`', 'secedit_file': `'$secedit_file`','audit_content': `'$audit_content`'}"

# Set up AUDIT_OUT
#$outfile
if ([string]::IsNullOrEmpty($outfile)){
    $AUDIT_OUT = "$AUDIT_CONTENT_LOCATION\audit_$host_os_hostname_$host_epoch.json"
    }
else {
    $AUDIT_OUT = "$outfile"
    }

$AUDIT_ERR = "$AUDIT_CONTENT_LOCATION\audit_$host_os_hostname_$host_epoch.err"

# create empty file - dont output
New-Item -ItemType file $AUDIT_OUT | Out-Null
#New-Item -ItemType file $AUDIT_ERR | Out-Null


# run audit

Write-Host "`nRunning Audit"
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


# Summary of Output

if ( Select-String $BENCHMARK $AUDIT_OUT )
    { 
       
       $audit_summary=Get-Content "$AUDIT_OUT" -tail 8
       Write-Host "Audit Successful`n" -ForegroundColor green
       Write-Host "$audit_summary"
       Write-Host "`nComplete audit file can be found at $AUDIT_OUT"
    }
else
    {
       Write-Host "Fail Audit - There were issues when running the audit please investigate" 
    }
