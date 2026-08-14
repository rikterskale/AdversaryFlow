# CLI reference

`adversaryflow` is the installed command. It uses `argparse`; required options are enforced by the parser. Commands return JSON where stated below. Handled operational failures return exit code `1`; `doctor` and `provider validate` return `0` when valid and `1` otherwise.

## Read-only and preparation commands

| Command | Purpose |
|---|---|
| `validate ROE` | Validate and print RoE engagement metadata. |
| `plan --roe ROE --actor ACTOR --technique ID [--target local-lab] [--audit artifacts/audit.jsonl]` | Fetch the MITRE ATT&CK Enterprise STIX bundle and produce a dry-run technique plan. This command requires network access; it never executes a campaign. |
| `intel-sync --actor ACTOR [--platform windows] [--target local-lab] [--catalog PATH] [--output artifacts/intel/enriched] [--mitre-only]` | Fetch the actor's MITRE ATT&CK relationships and matching CTID plan metadata, fill catalog gaps with synthetic-only marker abilities and benign procedures, and write a reviewable emulation plan. Imported commands, payloads, and setup instructions are discarded. |
| `draft --roe ROE --actor ACTOR --objective OBJECTIVE [--target local-lab] [--platform linux] [--catalog content/abilities/catalog.json]` | Produce an offline draft. |
| `guide [--actor APT29] [--target local-lab] [--objective "validate endpoint process visibility"] [--interactive]` | Print a campaign walkthrough; it does not create a campaign. |
| `capabilities` | Print `capabilities.json`. |
| `adapter status [--name local-synthetic|local-behavioral] [--catalog PATH|curated-windows]` | Read-only report of a fixed adapter, its contract version, allowed scopes, and catalog compatibility. |

## Diagnostics and support

| Command | Purpose |
|---|---|
| `doctor [--roe examples/roe.yaml] [--catalog content/abilities/catalog.json] [--json] [--fix]` | Check platform, Python, PyYAML, RoE, catalog, execution-adapter readiness, loopback, and offline mode. `--fix` creates local artifact folders only. |
| `support-bundle [--output artifacts/support] [--roe examples/roe.yaml]` | Create a redacted diagnostics ZIP. |
| `demo [--roe examples/roe.yaml] [--actor APT29] [--objective TEXT] [--approver NAME] [--catalog PATH] [--output artifacts/runs]` | Run the complete local synthetic demo. |

## Provider commands

`provider status`, `configure`, `diagnose`, and `validate` do not send a provider request. `provider test [--actor APT29] [--target local-lab] [--objective TEXT] [--roe examples/roe.yaml] [--platform linux] [--catalog PATH]` sends one planning request only when the provider is `openai-compatible`; it then applies the same RoE and safe-draft validation as campaign creation. It does not save, approve, or execute a campaign.

Profile commands: `provider profile list`; `provider profile status`; `provider profile use NAME`; `provider profile remove NAME`; and `provider profile save NAME --endpoint HTTPS_URL --model MODEL [--provider openai-compatible] [--credential-env ADVERSARYFLOW_API_KEY]`.

Policy commands: `provider policy status` and `provider policy allow NAME`. A hosted profile must have an exact allowlist entry for its provider, endpoint, and model before any provider request is made.

## Campaign commands

Create or resume a draft with `campaign [--roe examples/roe.yaml] [--actor ACTOR] [--target local-lab] [--objective TEXT] [--platform linux] [--catalog PATH] [--campaign-root artifacts/campaigns] [--campaign-id ID] [--fallback-offline]`. Creating a new draft requires `--actor` and `--objective`. Add `--approve --approver NAME [--output artifacts/runs]` only after review by the named RoE approver.

Lifecycle commands are: `campaign list [--campaign-root PATH]`; `campaign inspect --campaign-id ID [--campaign-root PATH]`; `campaign reject --campaign-id ID --approver NAME --reason TEXT [--campaign-root PATH]`; `campaign cancel --campaign-id ID --reason TEXT [--campaign-root PATH]`; and `campaign reset --campaign-id ID --confirm [--campaign-root PATH]`.

Use `--adapter local-behavioral --catalog curated-windows` after approval to execute the packaged fixed, read-only Windows behaviors. Use `campaign assess --campaign-id ID --telemetry-file FILE [--campaign-root PATH]` after a completed run to correlate independent EDR/SIEM JSONL observations. Behavior success, telemetry observation, detection, and cleanup are reported separately. See [CURATED_ABILITIES.md](CURATED_ABILITIES.md).

`list` and `inspect` are read-only. `reject` and `cancel` record decisions. `reset` deletes the direct campaign directory beneath the configured root after explicit confirmation.

## Local manager

`manager [--host 127.0.0.1] [--port 8787] [--campaign-root artifacts/campaigns] [--roe examples/roe.yaml] [--catalog content/abilities/catalog.json] [--open]` starts the loopback-only guided workspace. The named RoE approver can approve and run a reviewed campaign through the fixed local-synthetic adapter after typed confirmation and integrity revalidation.

The workspace includes local provider-profile and policy setup (without credentials), provider readiness, MITRE ATT&CK dry-run planning, and redacted support-bundle generation.

See [USAGE.md](USAGE.md) for a safe end-to-end flow.
