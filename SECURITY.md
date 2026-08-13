# Security Policy

## Supported version

The current repository release is `0.2.3`. [VERIFY: supported-version maintenance window]

## Reporting a vulnerability

[VERIFY: private vulnerability-reporting contact or process]

Do not include credentials, provider keys, production target data, or exploit payloads in a public issue.

## Security boundaries

AdversaryFlow is designed for authorized, local synthetic simulation. The local manager binds only to loopback; it may create offline drafts and record rejection or cancellation decisions, but it cannot approve or execute a campaign. CLI approval checks the named RoE approver, and the emulation catalog restricts network scope to `none` or `loopback`.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).
