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
entries may still change local state, access credential-related stores, or
create network telemetry when an operator copies and runs them. Use only in an
authorized disposable lab, review safety metadata first, and verify cleanup.

The local HTTP service binds to loopback by default. Remote binding requires
the explicit --allow-remote option and is not recommended on untrusted
networks.
