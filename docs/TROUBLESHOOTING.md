# Troubleshooting

Start with the local diagnostic command:

```powershell
adversaryflow doctor --json
adversaryflow doctor --fix --json
adversaryflow support-bundle
```

`doctor --fix` creates missing local `artifacts/`, `artifacts/runs`, `artifacts/campaigns`, and `artifacts/support` directories. It does not alter system configuration or send a provider request.

## Installation and platform checks

The diagnostic reports the detected platform, Python version, PyYAML availability, RoE validity, ability-catalog validity, loopback binding, and offline mode. The supported platforms are Windows, Debian, Ubuntu, and Kali. Install Python 3.11 or newer when the Python check fails.

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

## Local manager

The manager must bind to loopback (`127.0.0.1`, `localhost`, or `::1`). It cannot bind to external interfaces. The browser workspace creates offline drafts and records rejection/cancellation only; approval and local emulation remain CLI actions.

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for exact command options.
