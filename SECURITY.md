# Security policy

## Supported versions

Security fixes are provided for the latest released minor version. Users
should upgrade to the newest release before reporting an issue.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository.
Do not open a public issue for a suspected vulnerability and do not include
credentials, private environment data, or weaponized proof-of-concept code.

Include the affected version, impact, prerequisites, a minimal non-destructive
reproduction, and any proposed mitigation. Maintainers will acknowledge a
report within five business days and coordinate validation, remediation, and
disclosure.

## Product boundary

AdversaryFlow produces lab plans and never executes catalog commands. Catalog
entries may still change local state when an operator copies and runs them.
Use only in an authorized disposable lab you control, review safety metadata
first, and verify cleanup. See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

The local HTTP service binds to loopback by default. Remote binding requires
the explicit --allow-remote option and is not recommended on untrusted
networks.

## Threat model (local planner)

Treat the HTTP service as a single-operator lab UI, not a multi-user production
API. The trusted computing base is the operator's workstation, the pinned
runtime set, and the cached ATT&CK bundle. Untrusted inputs are JSON plan
imports, ATT&CK STIX downloads, and any host the operator pastes a command
onto. Execution kits are rebound to the live catalog so a browser-supplied
command string cannot be packaged as an official runner. Bounded synthetic
receipts are self-reported; correlate them with endpoint or SIEM telemetry
before treating execution as independently proven.
