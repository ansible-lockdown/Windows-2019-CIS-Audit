# Setup Windows Audit

## Overview

These are a guide to setting up the ability to run the ansible-lockdown audit content on a host without the remediation role.
The remediation role can also setup and run this audit as part of its tasks details of how this can be done are found in the README or the documentation of the audit content.

This audit runs on the host does not run across the network, this is to isolate the CPU, Network requirements to the host being audited.

Be aware that any audit on multiple hosts at the same time as part of the same platform or utilising shared products (e.g. storage) may have an impact.

## System Requirements

- Windows 2016+
- Powershell 5.1+
- Audit content
- Goss 0.3.16 (still alpha)
  - Binary link goss-alpha-windows-amd64.exe
- User Administrator rights (Security/Audit permissions potentially not yet tested)
- Latest GPO update applied (where applicable)

The Audit is able to run on the following:

- Domain member
- Domain controller
- Standalone server

## Steps

1. Download the relevant audit for your Operating system
2. Place that audit into an accessible location
3. Ensure the goss binary is in accessible location
4. Have a directory to output the audits to created (if doesn’t exist)
5. Edit the top variables section on run_audit.ps1

Where relevant update the following to match your solution:

- $AUDIT_BIN = "C:\vagrant\goss.exe"
- $AUDIT_CONTENT_LOCATION = "C:\vagrant"
