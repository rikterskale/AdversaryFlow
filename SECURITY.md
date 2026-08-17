# Security Policy

## Project status and supported versions

AdversaryFlow is an internal development project. No release is currently designated for security maintenance, and no supported-version maintenance window is offered.

## Reporting a vulnerability

No repository-specific private security-reporting channel is declared in this checkout. Until maintainers publish one, do not submit sensitive details through public issues; use the security-reporting process provided by the owning organization.

Do not include credentials, provider keys, production target data, or exploit payloads in repository issues.

## Security boundaries

AdversaryFlow is designed for authorized, local simulation. The local manager binds only to loopback. It can create drafts, record rejection or cancellation decisions, and approve and run a reviewed campaign only through the fixed `local-synthetic` adapter after exact RoE-approver identity, campaign-specific typed confirmation, and integrity checks. CLI approval also checks the named RoE approver. The `local-behavioral` and `idpt-local` adapters are not available through the browser approval path, and all built-in adapters restrict network scope to `none` or `loopback`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
