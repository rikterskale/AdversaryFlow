# Troubleshooting

Start with the local diagnostic command:

```powershell
adversaryflow doctor --json
adversaryflow doctor --fix --json
adversaryflow support-bundle
```

For a newcomer-oriented readiness summary, run `adversaryflow quickstart`. It combines the local checks with the canonical next-step commands; add `--fix` to create only the safe local artifact folders.

`doctor --fix` creates missing local `artifacts/`, `artifacts/runs`, `artifacts/campaigns`, and `artifacts/support` directories. It does not alter system configuration or send a provider request.

## Installation and platform checks

The diagnostic reports the detected platform, Python version, PyYAML availability, RoE validity, ability-catalog validity, execution-adapter readiness, loopback binding, and offline mode. The supported platforms are Windows, Debian, Ubuntu, and Kali. Install Python 3.11 or newer when the Python check fails.

## RoE or catalog errors

Use the configured paths with `doctor` to identify the failing file:

```powershell
adversaryflow doctor --roe examples/roe.yaml --catalog content/abilities/catalog.json
```

An RoE must include an engagement name, operator name, approver name, and approved targets, and must retain `dry_run: true`. Catalog abilities require expected telemetry, `writes_only_run_root: true`, and network scope of `none` or `loopback`.

## Provider recovery

Offline mode is the default and needs no credential. For hosted configuration, run:

```powershell
adversaryflow provider status
adversaryflow provider validate
adversaryflow provider diagnose
adversaryflow provider profile status
```

The supported hosted provider is `openai-compatible`; its endpoint must use HTTPS. `provider test` is the only provider command that sends a planning request. If a hosted campaign draft fails, rerun the campaign with `--fallback-offline` to create a local rehearsal draft.

## Campaign recovery

Use `campaign list` and `campaign inspect --campaign-id campaign-...` before recording a decision. A rejected or cancelled campaign remains an auditable local record. A completed campaign cannot be cancelled. `campaign reset --campaign-id campaign-... --confirm` deletes only the direct campaign directory under the configured campaign root.

If resume reports an integrity mismatch, do not approve the record; create a new reviewed draft. See [USAGE.md](USAGE.md).

## IDPT integration

IDPT execution is intentionally stricter than the synthetic and behavioral adapters. Start with the read-only readiness check:

```powershell
$env:ADVERSARYFLOW_IDPT_ROOT = "C:\Tools\IDPT-Emulation"
adversaryflow adapter status --name idpt-local --catalog idpt-windows-collection
```

The configured directory must contain `src/cli.mjs`, be pinned to the reviewed commit shown in [IDPT_INTEGRATION.md](IDPT_INTEGRATION.md), and have no modified tracked files. Git and Node.js 20 or newer must be available on `PATH`. If readiness fails, do not bypass the check by changing the catalog or using an unreviewed commit; correct the checkout and rerun the status command.

If the error says that the scenario or ability mapping is unexpected, confirm that the draft was created with `--catalog idpt-windows-collection` and that every selected ability comes from that packaged catalog. A different or partial ability set cannot use the reviewed IDPT scenario.

If execution reports plan identity, host, technique, run identity, or evidence-integrity failure, treat the run as untrusted. Do not use its evidence for validation. Preserve the run-owned diagnostics, inspect the checkout and configuration, and create a new reviewed campaign after correcting the cause.

If IDPT behavior succeeds but the report says telemetry is not configured, this is expected until matching offline EDR/SIEM observations are normalized and supplied to `campaign assess`. IDPT evidence verification and detection assessment are separate results.

## Local manager

The manager must bind to loopback (`127.0.0.1`, `localhost`, or `::1`). It cannot bind to external interfaces. The browser workspace creates drafts and records rejection/cancellation. It can also approve and run a reviewed campaign through the fixed `local-synthetic` adapter after exact RoE-approver identity, campaign-specific typed confirmation, and integrity checks. `local-behavioral` and `idpt-local` execution remain CLI actions.

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for exact command options.
