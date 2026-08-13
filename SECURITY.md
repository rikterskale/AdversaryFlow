# Security Policy

## Project status and supported versions

AdversaryFlow is an internal development project. No release is currently designated for security maintenance, and no supported-version maintenance window is offered.

## Reporting a vulnerability

Use the organization's established internal security-reporting process. [VERIFY: internal security-reporting channel or process]

Do not include credentials, provider keys, production target data, or exploit payloads in repository issues.

## Security boundaries

AdversaryFlow is designed for authorized, local synthetic simulation. The local manager binds only to loopback; it may create offline drafts and record rejection or cancellation decisions, but it cannot approve or execute a campaign. CLI approval checks the named RoE approver, and the emulation catalog restricts network scope to `none` or `loopback`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
