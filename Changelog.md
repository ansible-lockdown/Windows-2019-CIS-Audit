# Changes to Windows-2019-CIS-Audit

## Based on CIS Benchmark v5.0.0
## October 2026 - spec folders

- spec folders follow the role's task files, as Windows-2022-CIS-Audit does, e.g. section_1/section_1.1 -> section_1/section_1.1.x
- README and Changelog name the public Windows-2019-CIS role
- run_audit.ps1 secedit note describes what Server 2019 does, was a Server 2025 note
- README: the remediation role warns on 2.3.5.4 on a domain controller rather than writing it

## Based on CIS Benchmark v5.0.0
## October 2026 - generated from the remediation role

- Specs generated from Windows-2019-CIS in the Windows-2025-CIS-Audit layout, Goss format, run with syver
  - Each spec is the Windows-2025-CIS-Audit spec for the control whose remediation task is identical, renumbered, retitled and gated for CIS v5.0.0
  - 398 of the 400 recommendations asserted; 2.2.34 and 2.3.10.9 have no assertable state
- 2.2.30 asserts LOCAL SERVICE, NETWORK SERVICE, the v5.0.0 value the role sets
- 2.2.32 and 2.2.33 assert the base Impersonate a client after authentication holders, with RESTRICTED SERVICES\PrintSpoolerService and IIS_IUSRS optional
- 18.4.4 asserts EnableCertPaddingCheck under the native and Wow6432Node keys
- 18.4.6 asserts LSA Protection, RunAsPPL under Control\Lsa
- 18.7.1 asserted at Level 1 on domain controllers and member servers, as v5.0.0 sets it
- 19 MS only controls asserted on any server that is not a domain controller, as the role applies them
- Section 1 account policy and 2.3.11.6 reported as skipped on a domain joined host, with the reason in meta.skip_reason
- NGWS controls asserted only when win19cis_ngws is true
- run_audit.ps1, goss.yml, vars/CIS.yml, collector_targets.json and coverage.json for Windows Server 2019
- Initial release - beta, pending feedback. Please raise an issue or reach us on
  Discord with anything it gets wrong, reports unexpectedly, or misses
