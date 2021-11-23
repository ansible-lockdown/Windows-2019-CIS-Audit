[CmdletBinding()]
  param (
    [Parameter()]
    [string]$filename,
    
    [Parameter(Mandatory,ParameterSetName = 'policyname')]
    [string]$policyname,

    [Parameter(Mandatory,ParameterSetName = 'folderid')]
    [string]$folderid
      
    )
    if ([string]::isNullorEmpty($filename))  
    {
      "filename has not been set" 
      Exit 1
    }

    if ($policyname) {
       $pattern = 'Policy:(\s+)' +[regex]::escape($policyname) +'(.*?)GPO:'
       $file = Get-Content $filename
       $result = [regex]::match($file, $pattern).Value -replace ('\s+', ' ') -replace ('GPO:', ' ') 2>&1
    }
    elseif ($folderid){
      $pattern = 'Select-String -SimpleMatch -Pattern $folderid -path $file -context 0,2' 
      $result = $pattern -replace ('\s+', ' ')  2>&1
    }
     
          if($result) {
              $output = echo $result
              Write-Output $output
              } 
          else {
              "Not Defined"
              }

## How to Use
##
## ./gpo_regex.ps1 -filename c:\goss\regex_testing\gpresult.txt -policyname SystemTimePrivilege