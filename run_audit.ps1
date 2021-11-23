[CmdletBinding()]
param (
      [string] $group,
      [string] $outfile
)


# Set Variables for Audit
$BENCHMARK = "CIS"
$AUDIT_BIN = "C:\temp\goss.exe"
$AUDIT_FILE = "goss.yml"
$AUDIT_VARS = "vars\$BENCHMARK.yml"
$AUDIT_CONTENT_LOCATION = "C:\temp"
$AUDIT_CONTENT_VERSION = "Windows2019-$BENCHMARK-Audit"
$AUDIT_CONTENT_DIR = "$AUDIT_CONTENT_LOCATION\$AUDIT_CONTENT_VERSION"



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
  auditpol.exe /get /category:* > $AUDIT_CONTENT_LOCATION/auditpol_$AUDIT_TIME.txt
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
  auditpol.exe /get /category:* > $AUDIT_CONTENT_LOCATION auditpol_$AUDIT_TIME.txt
}


# get metadata
$machine_uuid=(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
$epoch=$AUDIT_TIME
$os_locale=(Get-TimeZone).Id
$os_version=(([System.Environment]::OSVersion.Version).build)
$os_hostname=(hostname)


$AUDIT_JSON_VARS = "'{
'machine_uuid':'$machine_uuid',
'epoch':'$epoch',
'os_locale':'$os_locale',
'audit_run':'wrapper',
'os_release':'$os_version',
'windows2019cis_os_distribution':'$os_name',
'os_hostname':'$os_hostname',
'auto_group':'$auto_group'
}'"

# Set up AUDIT_OUT
#$outfile
if ([string]::IsNullOrEmpty($outfile)){
    $AUDIT_OUT = "$AUDIT_CONTENT_LOCATION\audit_$os_hostname_$epoch.json"
    }
else {
    $AUDIT_OUT = "$outfile"
    }


# run audit

$AUDIT_BIN -g $AUDIT_CONTENT_DIR/$AUDIT_FILE --vars $AUDIT_CONTENT_DIR/$AUDIT_VARS  --vars-inline $AUDIT_JSON_VARS v -f json -o pretty > $AUDIT_OUT

if ( Select-String $BENCHMARK $AUDIT_OUT )
{ 
    echo "Success Audit"
    (Get-Content -tail -7 $AUDIT_OUT)
    Completed file can be found at $AUDIT_OUT
}
else
{
    echo "Fail Audit - There were issues when running the audit please investigate $AUDIT_OUT"
}
