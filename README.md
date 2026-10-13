# Windows Server 2019 Audit

## Overview

### Based on CIS Microsoft Windows Server 2019 Benchmark v4.0.0

[Centre For Internet Security]

**This audit component is in beta while we gather feedback.** It is usable and its
results are meaningful, and we would like to hear how it behaves on your estate -
what it gets wrong, what it reports that you did not expect, and what is missing.
Please raise an issue, or come and talk to us on the [Discord Server](https://www.lockdownenterprise.com/discord).
Expect the specs and the variables they read to change in response.

This repository is a set of configuration files and directories to run the audit
of the relevant benchmark of Windows Server 2019, as a member server or as a
domain controller.

It is configured in a directory structure level, one file per control, matching
the layout of the Linux audit repositories.

The content is generated from `Private-Windows-2019-CIS`, so the audit asserts
what the remediation role actually does rather than a separately maintained
restatement of it. Each spec is the Windows-2025-CIS-Audit spec for the control
whose remediation task is identical in the 2019 role, renumbered, retitled and
gated for the 2019 benchmark; 2.2.31, 18.4.4 and 18.4.6 differ from their
Windows-2025-CIS-Audit counterparts and are finished by hand. Files carry a
manifest (`.audit-generated.json`).

## Server profiles

A Server benchmark splits by host role as well as by level. Of the 433
recommendations, 371 apply to both a domain controller and a member server, 28
are DC only and 34 are MS only. `win19cis_system_role` selects which, and
`run_audit.ps1` derives it from `Win32_ComputerSystem.DomainRole` rather than
asking for it, so it cannot silently disagree with the host.

The two axes do not factor. Control 18.7.1 is Level 1 on a domain controller and
Level 2 on a member server, so no pair of role and level booleans can express
it. The generated gates use the cross product, and collapse to a bare level gate
for the 368 controls that apply identically to both roles.

CIS treats any server that is not a domain controller as a Member Server,
standalone included. The audit follows the remediation role: 18 of the MS only
controls are asserted on any server that is not a domain controller. The ones
that would cut off remote administration of a standalone server (2.2.22, 2.2.27,
18.4.1) or need a domain (LAPS, the Netlogon secure channel, cached domain logons)
are asserted on a member server only.

Next Generation Windows Security (NGWS) is an optional CIS profile. Its seven
controls (18.9.5.x Device Guard and Credential Guard)
are asserted only when `win19cis_ngws` is true, which defaults to false. The
remediation role applies them on the same switch and passes its value to the
audit, so the two agree.

## What this audit asserts, and what it deliberately does not

A Windows setting and the registry key a playbook writes are not always the same
thing. Account policy and account lockout policy live in the SAM and are only
reachable through `secedit`; a registry write to `Control\Lsa` reports success
and applies nothing. So sections 1.1, 1.2 and the `System Access` controls in
2.3.x are audited through the effective policy, never through the key the
remediation role happens to write.

Two consequences worth stating plainly, both proven against live hosts:

- **Account policy is domain scoped.** On a domain joined host the Default
  Domain Policy overwrites local `[System Access]` at every refresh, so the ten
  secedit backed section 1 controls cannot hold locally there. The remediation
  role skips them and warns; this audit reports them as skipped, with the
  reason in `meta.skip_reason`, so the count still adds up. To meet CIS section 1 on a member server, set it in the Default Domain
  Policy. 2.3.11.6 (`ForceLogoffWhenHourExpire`) is also a `[System Access]`
  value the Default Domain Policy sets, so it is skipped the same way.
- **Group Policy outranks a registry write on a domain controller.** Control
  2.3.5.4 applies and is then reverted at the next policy refresh. It is
  expected to fail on a DC hardened by the remediation role; set it in the
  Default Domain Controllers Policy instead.
- **2.2.31 asserts the benchmark value.** Generate security audits is expected to
  hold `LOCAL SERVICE, NETWORK SERVICE`, the CIS v4.0.0 value the remediation
  role applies.

Controls that cannot be asserted are recorded in `coverage.json` with a reason
code rather than being given an assertion that always passes. The table below is
generated from that file, so it cannot overstate what is checked.

## Files in this repository

Alongside the `section_*` directories, these are generated with the specs:

**`goss.yml`** - the gossfile, and the entry point syver is pointed at. It lists
which section directories to load, gated per section, and holds the snapshot
canaries and the run metadata.

**`vars/CIS.yml`** - every switch the audit reads: the per-rule toggles, the
level and host-role selectors, and the site tunables seeded from the
remediation role's defaults. This is the file to edit to change what the audit
checks on a given host.

**`collector_targets.json`** - the shopping list for `run_audit.ps1`. It names
the secedit keys, privilege rights, auditpol subcategories, services, firewall
profiles and per-user hives to snapshot. Most of this benchmark is not readable
by a goss resource, so the collector gathers it once and the specs match against
the result; generating this list beside the specs is what stops the set
collected and the set asserted drifting apart.

**`coverage.json`** - one entry per benchmark rule recording whether it was
asserted and, when it was not, why. The coverage table at the end of this README
is generated from it.

**`.audit-generated.json`** - a hash of each generated file, so a regeneration
can tell an untouched file from one somebody has edited.

## Which binary runs this

The content is Goss format, the same as every other Ansible-Lockdown audit
repository. It is run with [syver](https://github.com/krameff/syver), the Goss
fork that adds Windows support.

Two things about syver on Windows:

- It refuses to run without `--use-alpha=1`. `run_audit.ps1` passes it.
- From 0.11.0, a check it cannot run is reported as an ERROR rather than being
  allowed to pass quietly. That behaviour is what makes a green run mean
  something, so 0.11.0 is the minimum worth trusting.

## Running it

`run_audit.ps1` collects a policy snapshot once and the audit matches against
it, rather than each control shelling out to `secedit` and contending on LSA.
What is collected comes from `collector_targets.json`, which is generated
alongside the specs, so the set collected and the set asserted cannot drift
apart.

```powershell
# collect and audit, JSON out
.\run_audit.ps1 -Format json -SystemType Server -OutFile C:\ProgramData\audit_logs\audit.json

# collect only, to eyeball the snapshot before trusting a run
.\run_audit.ps1 -CollectOnly
```

The audit must be staged clean. `win_unzip` and similar overlay rather than
replace, and a spec the generator has since withdrawn will survive on the host.
One unparseable file aborts the entire run, not one control, so an orphan left
behind takes out every assertion.

## Expected failures

A control the remediation role deliberately skips will fail here, and that is
correct. `win_skip_for_test` in the role skips the WinRM block, RDP deny logon,
the public firewall profile, the administrator rename, and the two network logon
rights that would otherwise sever the control connection. Those show as failures
until the role is run with `win_skip_for_test: false`.

Some controls name a principal that only exists when an optional feature is
installed - Hyper-V for 2.2.19, IIS for 2.2.33, Exchange for 2.2.38. The
feature-dependent principal is matched as an optional group, so these pass on a
host with the feature and on one without it. That is deliberately lenient in one
direction: a host that grants the principal without having the feature also
passes. The remediation role discovers the feature state in prelim, so a future
version can assert the exact membership per branch.

<!-- BEGIN COVERAGE (generated from coverage.json - do not edit) -->

| Section | In benchmark | Asserted | Coverage |
| --- | --- | --- | --- |
| 1 | 10 | 10 | 100% |
| 2 | 121 | 119 | 98% |
| 5 | 2 | 2 | 100% |
| 9 | 23 | 23 | 100% |
| 17 | 34 | 34 | 100% |
| 18 | 231 | 231 | 100% |
| 19 | 12 | 12 | 100% |
| **All** | **433** | **431** | **99.5%** |

### Not asserted

| Rule | Title | Reason |
| --- | --- | --- |
| 2.2.34 | Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group' | NO_ASSERTABLE_STATE |
| 2.3.10.9 | Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured | NO_ASSERTABLE_STATE |

### Controls that branch on state discovered at run time

These pick *which* value is correct from something a gossfile
template cannot see - whether Hyper-V or IIS is installed, whether
an account has been renamed, what a site variable was set to. Each
asserts the part that holds on every host; the feature-dependent
part is matched optionally rather than required.

2.2.19, 2.2.33, 2.2.38, 2.3.1.3, 2.3.1.4

<!-- END COVERAGE -->

## Support

[Discord Community Discussions]

[Enterprise Support]

[MindPoint Group]

## Contributing

Bug reports and feature requests are welcome from everyone, please raise an issue.

Pull requests are accepted from approved contributors only. To be onboarded, join the [Discord Server](https://www.lockdownenterprise.com/discord) and request contributor access. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

## Links and Further information

- [Centre For Internet Security]

<!----
README Links
---->

[benchmark-type]: CIS
[OS-VERSION]: Windows2019
[os-type]: Windows
[Centre For Internet Security]: https://www.cisecurity.org
[Read the Docs - Audit]: https://ansible-lockdown.readthedocs.io/en/latest/audit/getting-started-audit.html
[MindPoint Group]: https://mindpointgroup.com/cybersecurity-consulting/automate/baseline-modernization#GH_LockdownReadMe
[Discord Community Discussions]: https://www.lockdownenterprise.com/discord
[Enterprise Support]: https://lockdownenterprise.com#GH_LockdownReadMe
