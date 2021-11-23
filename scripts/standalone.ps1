## script used to parse the output of a file created by
## secedit /export /cfg c:\{{ some filename here}}
## it is used to capture the value of a local security settings
## .\standalone.ps1 -filename C:\securityconfig_updated.cfg -localname MinimumPasswordAge

[CmdletBinding()]
param (
      [string] $filename,
      [string] $localname
)
#$file = "C:\goss\securityconfig.txt"
#$localname = "MinimumPasswordAge"

if ([string]::isNullorEmpty($filename) -Or [string]::isNullorEmpty($localname) ) {
  "filename or localname has not been set" 
  Exit 1
}

else
{
$pattern =(Select-String -SimpleMatch -Pattern $localname -path $filename )
#$pattern = 'Policy:(\s+)' +[regex]::escape($policyname) +'(.*?)GPO:'
$result = $pattern.line
    if($result) {
        $output = echo $result
        Write-Output $output
    } Else {
        $output = "Not Defined"
        Write-Output $output
    }
}