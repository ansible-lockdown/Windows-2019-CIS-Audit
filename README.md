# Windows 2019 CIS audit

## Overview

**This is a BETA release.**

This is the start of the layout for windows goss framework
It has the following setup

- goss.yml - the main goss file to run (has to be used with a -g) - this loads all the sections as required
- (benchmark_name).yml - These are the variable used as part of the goss file - this is split into sections to control the variables - will get BIG

- Try to reuse as much as possible
- use variables where you can to shorten and be more efficient in the code
- Build variables up
- Some control only work on DC or MS - settings in Vars to determine (will be populated by ansible when run from task)
- some controls written twice (due to different vars for a DC or MS)e.g. 2.2.7

### How it works

- The audit is designed to run as part of the ansible remediation playbook (coming soon)

 or

- The standalone configurable script contained within this repo run_audit.ps1
  - This script discovers and sets several variables to ensure consistent running of the command.

#### NOTE: Its expected to run from audit dir or to amend the script paths in vars accordingly

- When goss runs it will run the required OS commands to capture the data for analysis.

  - GPO settings goss runs the powershell script ./scripts/gpo_regex.ps1 with arguments is run to search for the matching policy name
    - Will output the details if defined
    - if nothing is found will output "Not Defined"

Ability to audit a local system using a lightweight binary to check the current state.

This is:

- very small 11MB
- lightweight
- self contained

Due to the variations that can occur within windows this is released as beta.
It has been tested on base installation

- standalone system
- domain controller

Detailed:

There are a couple of settings in the wrapper script using varaibles for file locations. These need to be correct.

[How To Guide](Docs/Security_remediation_and_auditing.MD)

## Join us

On our [Discord Server](https://discord.gg/JFxpSgPFEJ) to ask questions, discuss features, or just chat with other Ansible-Lockdown users

## Requirements

- Permissions to run all the commands may need admin to run this
  - also if iis or exchange is installed

- download goss (current version 0.3.6 - Alpha for windows)
  - [x86_64-goss](https://github.com/aelsabbahy/goss/releases/download/v0.3.goss-alpha-windows-amd64.exe)
  - validate SHA

- Suggest reboot and gpupdate is run prior to audit - will potentially give differing results

## Not using wrapper script information

These are just some of the requirements needed if running goss standalone.
Please refer to goss documentation if running manually.

- Goss to be on the host running the audit _ note its current alpha but works well
  - need to set environment

```txt
$env:GOSS_USE_ALPHA=1
```

### Domain members and domain controllers

- gpresult /v /r > file_location.txt need to be created (variable gpresult_file  needs to be updated)
- auditpol.exe /get /category:* > file_location.txt ( the variable auditresults_file needs to be updated)

### If standalone server will require the following commands

- secedit /export /cfg {{ file output location }} ( variable standalone_policies.txt )
- auditpol.exe /get /category:* > file_location.txt
- Due to the output we need to search for SID for std users using the MS doc below
  - [Microsoft_security_identifiers](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows)
  - also added to vars for completeness

## further information

- [goss documentation](https://github.com/aelsabbahy/goss/blob/master/docs/manual.md#patterns)
- [CIS standards](https://www.cisecurity.org)

## Example output (standalone after running benchmark)

```ps
PS C:\vagrant\Win2019-CIS-Audit> .\run_audit.ps1
Pre checks - Ensure files exist
OK - "C:\vagrant\goss.exe" exists
OK - "C:\vagrant\Win2019-CIS-Audit\CIS.yml" exists
OK - "C:\vagrant\Win2019-CIS-Audit\goss.yml" exists
OK - Files Exist
Running Audit commands

OK - ran auditpol report - created C:\vagrant\auditpol_1646394033.txt

StandAlone Server system discovered running relevant checks

OK - secedit report - created C:\vagrant\secedit_1646394033.txt

Running Audit
Audit Successful

    "summary": {         "failed-count": 31,         "summary-line": "Count: 661, Failed: 31, Duration: 44.994s",         "test-count": 661,         "total-duration": 44993809300     } }

Complete audit file can be found at C:\vagrant\audit_1646394033.json
PS C:\vagrant\Win2019-CIS-Audit>
```
