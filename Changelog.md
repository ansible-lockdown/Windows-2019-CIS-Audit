# Changes to Windows-2019-CIS-Audit

## Based on CIS Benchmark v4.0.0
## October 2026 - generated from the remediation role

- Specs generated from Private-Windows-2019-CIS in the Windows-2025-CIS-Audit layout, Goss format, run with syver
  - Each spec is the Windows-2025-CIS-Audit spec for the control whose remediation task is identical, renumbered, retitled and gated for CIS v4.0.0
  - 431 of the 433 recommendations asserted; 2.2.34 and 2.3.10.9 have no assertable state
- 2.2.31 asserts LOCAL SERVICE, NETWORK SERVICE, the v4.0.0 value the role sets
- 18.4.4 asserts EnableCertPaddingCheck under the native and Wow6432Node keys
- 18.4.6 asserts LSA Protection, RunAsPPL under Control\Lsa
- 18 MS only controls asserted on any server that is not a domain controller, as the role applies them
- Section 1 account policy and 2.3.11.6 reported as skipped on a domain joined host, with the reason in meta.skip_reason
- NGWS controls asserted only when win19cis_ngws is true
- run_audit.ps1, goss.yml, vars/CIS.yml, collector_targets.json and coverage.json for Windows Server 2019
- Initial release - beta, pending feedback. Please raise an issue or reach us on
  Discord with anything it gets wrong, reports unexpectedly, or misses
