# CLI reference

`adversaryflow` is the installed command. It uses `argparse`; required options are enforced by the parser. Commands return JSON where stated below. Handled operational failures return exit code `1`; `doctor` and `provider validate` return `0` when valid and `1` otherwise.

Parser usage errors, including missing required arguments or an unknown command, use argparse's standard non-zero usage-error exit. Read-only and preparation commands do not approve or execute a campaign unless their command description explicitly says otherwise. The browser manager has a separate HTTP action surface described in [the local-manager guide](modules/local-manager.md).

## Read-only and preparation commands

| Command | Purpose |
|---|---|
| `validate ROE` | Validate and print RoE engagement metadata. |
| `plan --roe ROE --actor ACTOR --technique ID [--target local-lab] [--audit artifacts/audit.jsonl]` | Fetch the MITRE ATT&CK Enterprise STIX bundle and produce a dry-run technique plan. This command requires network access; it never executes a campaign. |
| `intel-sync --actor ACTOR [--platform windows] [--target local-lab] [--catalog PATH] [--output artifacts/intel/enriched] [--mitre-only]` | Fetch the actor's MITRE ATT&CK relationships and matching CTID plan metadata, fill catalog gaps with synthetic-only marker abilities and benign procedures, and write a reviewable emulation plan. Imported commands, payloads, and setup instructions are discarded. |
| `draft --roe ROE --actor ACTOR --objective OBJECTIVE [--target local-lab] [--platform linux] [--catalog content/abilities/catalog.json]` | Produce an offline draft. |
| `guide [--actor APT29] [--target local-lab] [--objective "validate endpoint process visibility"] [--interactive]` | Print a campaign walkthrough; it does not create a campaign. |
| `capabilities` | Print `capabilities.json`. |
| `adapter status [--name local-synthetic|local-behavioral|idpt-local] [--catalog PATH|curated-windows|curated-linux|curated-macos|idpt-windows-collection]` | Read-only report of a fixed adapter, its contract version, allowed scopes, catalog compatibility, and IDPT registry selection when applicable. |
| `coverage [--campaign-root artifacts/campaigns]` | Return the read-only actor → technique → behavior → telemetry → detection → retest dashboard data. |
| `detection export [--catalog PATH] [--output artifacts/detection-mappings]` | Export Sigma, Sentinel KQL, Splunk SPL, and Elastic EQL validation templates. No rule is deployed. |

## Telemetry commands

`telemetry normalize --source generic|sentinel|defender|splunk|elastic|crowdstrike --input EXPORT --output NORMALIZED.jsonl` converts an offline vendor export to the `ADVERSARYFLOW-TELEMETRY-1` schema. `telemetry preflight --sensor-manifest HEALTH.json [--catalog PATH] [--target local-lab]` validates declared source coverage, clock sync, and agent health before execution. The post-run form, `telemetry preflight --run-dir RUN --telemetry-file NORMALIZED.jsonl`, checks correlation identifiers and timestamps. Neither form queries a sensor. `telemetry export --run-dir RUN --format json|csv --output FILE` exports the current assessment.

## Diagnostics and support

| Command | Purpose |
|---|---|
| `doctor [--roe examples/roe.yaml] [--catalog content/abilities/catalog.json] [--json] [--fix]` | Check platform, Python, PyYAML, RoE, catalog, execution-adapter readiness, loopback, and offline mode. `--fix` creates local artifact folders only. |
| `support-bundle [--output artifacts/support] [--roe examples/roe.yaml]` | Create a redacted diagnostics ZIP. |
| `demo [--roe examples/roe.yaml] [--actor APT29] [--objective TEXT] [--platform linux] [--approver NAME] [--catalog PATH] [--output artifacts/runs] [--adapter NAME]` | Run the complete approved local workflow with the selected fixed adapter. |

## Provider commands

`provider status`, `configure`, `diagnose`, and `validate` do not send a provider request. `provider test [--actor APT29] [--target local-lab] [--objective TEXT] [--roe examples/roe.yaml] [--platform linux] [--catalog PATH]` sends one planning request only when the provider is `openai-compatible`; it then applies the same RoE and safe-draft validation as campaign creation. It does not save, approve, or execute a campaign.

Profile commands: `provider profile list`; `provider profile status`; `provider profile use NAME`; `provider profile remove NAME`; and `provider profile save NAME --endpoint HTTPS_URL --model MODEL [--provider openai-compatible] [--credential-env ADVERSARYFLOW_API_KEY]`.

Policy commands: `provider policy status` and `provider policy allow NAME`. A hosted profile must have an exact allowlist entry for its provider, endpoint, and model before any provider request is made.

## Campaign commands

Create or resume a draft with `campaign [--roe examples/roe.yaml] [--actor ACTOR] [--target local-lab] [--objective TEXT] [--platform linux] [--catalog PATH] [--campaign-root artifacts/campaigns] [--campaign-id ID] [--fallback-offline]`. Creating a new draft requires `--actor` and `--objective`. Add `--approve --approver NAME [--output artifacts/runs] [--sensor-manifest HEALTH.json]` only after review by the named RoE approver. When supplied, the sensor manifest must pass before execution starts.

Lifecycle commands are: `campaign list [--campaign-root PATH]`; `campaign inspect --campaign-id ID [--campaign-root PATH]`; `campaign reject --campaign-id ID --approver NAME --reason TEXT [--campaign-root PATH]`; `campaign cancel --campaign-id ID --reason TEXT [--campaign-root PATH]`; `campaign reset --campaign-id ID --confirm [--campaign-root PATH]`; and `campaign retest --campaign-id ID [--campaign-root PATH]`, which creates a new immutable review draft from unresolved gaps.

Use `--adapter local-behavioral` with `--catalog curated-windows`, `curated-linux`, or `curated-macos` after approval to execute the corresponding packaged fixed, read-only local behaviors. Use `campaign assess --campaign-id ID --telemetry-file FILE [--window-seconds 300] [--campaign-root PATH]` after a completed run to correlate independent EDR/SIEM JSONL observations. Behavior success, telemetry observation, detection, ambiguity, and cleanup are reported separately. See [CURATED_ABILITIES.md](CURATED_ABILITIES.md).

Use `--adapter idpt-local --catalog idpt-windows-collection` to delegate the fixed benign Windows collection scenario to the exact reviewed IDPT checkout configured by `ADVERSARYFLOW_IDPT_ROOT`. See [IDPT_INTEGRATION.md](IDPT_INTEGRATION.md).

The safe IDPT command sequence is:

```powershell
$env:ADVERSARYFLOW_IDPT_ROOT = "C:\Tools\IDPT-Emulation"
adversaryflow adapter status --name idpt-local --catalog idpt-windows-collection
adversaryflow campaign --actor "IDPT Windows Collection Baseline" --platform windows --catalog idpt-windows-collection --objective "validate benign collection telemetry"
adversaryflow campaign --campaign-id campaign-... --catalog idpt-windows-collection --approve --approver manager@example.test --adapter idpt-local
adversaryflow campaign assess --campaign-id campaign-... --telemetry-file normalized.jsonl
```

The first command is read-only. The second creates a draft only. The third is the only command in this sequence that starts the approved IDPT-backed local run. The last command assesses separately supplied offline telemetry; it does not query IDPT or a production sensor.

`list` and `inspect` are read-only. `reject` and `cancel` record decisions. `reset` deletes the direct campaign directory beneath the configured root after explicit confirmation.

## Local manager

`manager [--host 127.0.0.1] [--port 8787] [--campaign-root artifacts/campaigns] [--roe examples/roe.yaml] [--catalog content/abilities/catalog.json] [--open]` starts the loopback-only guided workspace. The named RoE approver can approve and run a reviewed campaign through the fixed local-synthetic adapter after typed confirmation and integrity revalidation.

The workspace includes local provider-profile and policy setup (without credentials), provider readiness, MITRE ATT&CK dry-run planning, and redacted support-bundle generation.

See [USAGE.md](USAGE.md) for a safe end-to-end flow.
