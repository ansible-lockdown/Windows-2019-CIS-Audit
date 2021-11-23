[CmdletBinding()]
param (
      [string] $filename,
      [string] $policyname
)
#$file = "C:\goss\gpresult_r.txt"
#$policyname = "BackupPrivilege"

if ([string]::isNullorEmpty($filename) -Or [string]::isNullorEmpty($policyname) ) {
  "filename or policy name has not been set" 
  Exit 1
}

else
{
$pattern = 'Policy:(\s+)' +[regex]::escape($policyname) +'(.*?)GPO:'
$file = Get-Content $filename
$result = [regex]::match($file, $pattern).Value -replace ('\s+', ' ') -replace ('GPO:', ' ') 2>&1
    if($result) {
        $output = echo $result
        Write-Output $output
    } Else {
        "Not Defined"
    }
}
## How to Use
##
## ./gpo_regex.ps1 -filename c:\goss\regex_testing\gpresult.txt -policyname SystemTimePrivilege