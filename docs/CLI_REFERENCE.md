# CLI reference

`adversaryflow` is the installed command. It uses `argparse`; required options are enforced by the parser. Commands return JSON where stated below. Handled operational failures return exit code `1`; `doctor` and `provider validate` return `0` when valid and `1` otherwise. Run `adversaryflow --help` for the quick-start path. Use `adversaryflow --version` or `adversaryflow version` to identify the installed build. Shared defaults can be supplied with `--config defaults.json` before the command; validate them first with `adversaryflow config validate defaults.json`. Use `--quiet` with the loopback manager to suppress its startup banner. Shell completion is available with `adversaryflow completion bash|zsh|fish|powershell`.

Parser usage errors, including missing required arguments or an unknown command, use argparse's standard non-zero usage-error exit. Read-only and preparation commands do not approve or execute a campaign unless their command description explicitly says otherwise. The browser manager has a separate HTTP action surface described in [the local-manager guide](modules/local-manager.md).

## Global output options

Every command accepts the same output flags (place them after the command name, before any nested subcommand): `--json` forces machine-readable JSON, `--human` forces the readable text view, `--quiet` prints only a terse status line, `--verbose` includes extra detail where available, and `--no-color` disables ANSI colour. With no flag, output is auto-detected: a real terminal gets human-readable, severity-coloured text and a redirected/piped stream gets clean JSON, so scripts and CI stay deterministic. On an interactive terminal, mutating commands also print a will/will-not dry-run banner and step-progress indicators to stderr.

- `completion {bash,zsh,fish,powershell}` prints a shell completion script (e.g. `source <(adversaryflow completion bash)`). Generating a script contacts nothing.
- `explain [CODE]` prints the meaning of a process exit code, or the full table when no code is given. Documented codes: `0` success, `1` general error, `2` usage error (argparse). Codes `3`–`7` are reserved for scope, approval, provider, integrity, and not-found conditions.

## Read-only and preparation commands

| Command | Purpose |
|---|---|
| `validate ROE` | Validate and print RoE engagement metadata. |
| `version` | Print the installed package name and semantic version as JSON. |
| `interactive` or no command | Launch the guided local-lab terminal workflow. It checks readiness, collects scope and objective, creates a review draft, explains the approval boundary, and never runs until the exact approval phrase is entered. `--interactive` is also accepted globally. |
| `why TECHNIQUE [--catalog PATH]` | Explain a reviewed technique in plain language, including fixed lab behavior, expected detections, and safety boundary. |
| `explain-last [--run-dir PATH] [--output PATH]` | Summarize the newest local telemetry-gap report and optionally export a beginner-friendly Markdown follow-up. |
| `config validate FILE` | Validate supported shared JSON defaults without applying them. |
| `template save NAME --actor ACTOR --objective TEXT [--target local-lab] [--platform linux] [--root artifacts/templates]` / `template list --root artifacts/templates` | Create or list reusable local campaign templates; templates never approve or execute campaigns. |
| `schedule create NAME --template TEMPLATE --cadence-days DAYS [--root artifacts/schedules]` | Create a planned local retest schedule; it never starts a campaign automatically. |
| `plan --roe ROE --actor ACTOR --technique ID [--target local-lab] [--attack-bundle PATH] [--audit artifacts/audit.jsonl]` | Produce a dry-run technique plan. By default it fetches the MITRE ATT&CK Enterprise STIX bundle; `--attack-bundle` reads a local STIX JSON bundle instead for offline and deterministic use. It never executes a campaign. |
| `intel-sync --actor ACTOR [--platform windows] [--target local-lab] [--catalog PATH] [--output artifacts/intel/enriched] [--mitre-only]` | Fetch the actor's MITRE ATT&CK relationships and matching CTID plan metadata, fill catalog gaps with synthetic-only marker abilities and benign procedures, and write a reviewable emulation plan. Imported commands, payloads, and setup instructions are discarded. |
| `draft --roe ROE --actor ACTOR --objective OBJECTIVE [--target local-lab] [--platform linux] [--catalog content/abilities/catalog.json]` | Produce an offline draft. |
| `guide [--actor APT29] [--target local-lab] [--objective "validate endpoint process visibility"] [--interactive]` | Print a campaign walkthrough; it does not create a campaign. |
| `completion bash|zsh|fish|powershell` | Print installable command completion for the selected shell. |
| `capabilities` | Print `capabilities.json`. |
| `adapter status [--name local-synthetic|local-behavioral|idpt-local] [--catalog PATH|curated-windows|curated-linux|curated-macos|idpt-windows-collection]` | Read-only report of a fixed adapter, its contract version, allowed scopes, catalog compatibility, and IDPT registry selection when applicable. |
| `coverage [--campaign-root artifacts/campaigns]` | Return the read-only actor → technique → behavior → telemetry → detection → retest dashboard data. |
| `detection export [--catalog PATH] [--output artifacts/detection-mappings]` | Export Sigma, Sentinel KQL, Splunk SPL, and Elastic EQL validation templates. No rule is deployed. |
| `detection import --input RULES.json [--output artifacts/detection-rules]` / `detection score --rules RULES.json [--campaign-root PATH]` | Import offline detection rules and score them against local evidence without deploying or querying a vendor. |
| `retention preview [--campaign-root PATH]` / `retention cleanup --confirm [--campaign-root PATH]` | Preview or explicitly remove retention-eligible local campaign directories. |
| `branch --campaign-id ID --name NAME [--campaign-root PATH]` | Create a new review draft branch without copying approval decisions. |
| `coverage trends [--campaign-root PATH]` | Show read-only historical campaign, detection, and gap trends. |
| `catalog --source PATH --output PATH --name NAME --version SEMVER` | Create and validate a governed catalog draft. |
| `adapters [--catalog PATH]` | Show read-only compatibility for the fixed adapters. |
| `archive search [--query TEXT] [--tag TAG] [--campaign-root PATH]` | Search local campaign metadata by campaign ID, actor, objective, or tag. |
| `archive tag --campaign-id ID [--tags tag1,tag2] [--campaign-root PATH]` | Replace normalized local archive tags. |
| `archive controls --campaign-id ID --owner NAME --retention-days DAYS [--campaign-root PATH]` | Set local ownership and retention-review metadata. |
| `archive export --campaign-id ID [--output artifacts/exports] [--campaign-root PATH]` | Write a Markdown and PDF executive summary; it does not execute or approve a campaign. |

## Telemetry commands

`telemetry normalize --source generic|sentinel|defender|splunk|elastic|crowdstrike --input EXPORT --output NORMALIZED.jsonl` converts an offline vendor export to the `ADVERSARYFLOW-TELEMETRY-1` schema. `telemetry preflight --sensor-manifest HEALTH.json [--catalog PATH] [--target local-lab]` validates declared source coverage, clock sync, and agent health before execution. The post-run form, `telemetry preflight --run-dir RUN --telemetry-file NORMALIZED.jsonl`, checks correlation identifiers and timestamps. Neither form queries a sensor. `telemetry export --run-dir RUN --format json|csv --output FILE` exports the current assessment.

## Diagnostics and support

| Command | Purpose |
|---|---|
| `doctor [--roe examples/roe.yaml] [--catalog content/abilities/catalog.json] [--json] [--fix]` | Check platform, Python, PyYAML, RoE, catalog, execution-adapter readiness, loopback, and offline mode. `--fix` creates local artifact folders only. |
| `quickstart [--json] [--fix]` | Run the canonical first-user readiness check and print safe next steps. `--fix` creates local artifact folders only; no target or provider is contacted. |
| `support-bundle [--output artifacts/support] [--roe examples/roe.yaml]` | Create a redacted diagnostics ZIP. |
| `demo [--roe examples/roe.yaml] [--actor APT29] [--objective TEXT] [--platform linux] [--approver NAME] [--catalog PATH] [--output artifacts/runs] [--adapter NAME]` | Run the complete approved local workflow with the selected fixed adapter. |

## Provider commands

`provider status`, `configure`, `diagnose`, and `validate` do not send a provider request. `provider test [--actor APT29] [--target local-lab] [--objective TEXT] [--roe examples/roe.yaml] [--platform linux] [--catalog PATH]` sends one planning request only when the provider is `openai-compatible`; it then applies the same RoE and safe-draft validation as campaign creation. It does not save, approve, or execute a campaign.

Profile commands: `provider profile list`; `provider profile status`; `provider profile use NAME`; `provider profile remove NAME`; and `provider profile save NAME --endpoint HTTPS_URL --model MODEL [--provider openai-compatible] [--credential-env ADVERSARYFLOW_API_KEY]`.

Policy commands: `provider policy status` and `provider policy allow NAME`. A hosted profile must have an exact allowlist entry for its provider, endpoint, and model before any provider request is made.

## Campaign commands

Create or resume a draft with `campaign [--roe examples/roe.yaml] [--actor ACTOR] [--target local-lab] [--objective TEXT] [--platform linux] [--catalog PATH] [--campaign-root artifacts/campaigns] [--campaign-id ID] [--fallback-offline] [--adapter local-synthetic|local-behavioral|idpt-local]`. Creating a new draft requires `--actor` and `--objective`. On an interactive terminal, running `campaign` with neither `--campaign-id` nor `--actor`/`--objective` offers a numbered picker of saved campaigns to resume; non-interactively it fails with a usage error (exit code `2`). Add `--approve --approver NAME [--output artifacts/runs] [--sensor-manifest HEALTH.json]` only after review by the named RoE approver. When supplied, the sensor manifest must pass before execution starts.

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

The workspace includes local provider-profile and policy setup (without credentials), provider readiness, MITRE ATT&CK dry-run planning, and redacted support-bundle generation. The UI offers a light/dark/system theme toggle (keyboard `t`), a persistent readiness health badge, `1`–`9` keyboard navigation between sections, toast notifications, sortable/tag-filtered archive search, a structured scope-and-telemetry inspect view, and copy-to-clipboard CLI command blocks. All of these stay loopback-only and never contact an external target.

See [USAGE.md](USAGE.md) for a safe end-to-end flow.

Versioned output and input schemas are listed in [SCHEMAS.md](SCHEMAS.md).
# `quickstart`

Run the canonical first-user readiness flow:

```bash
adversaryflow quickstart
adversaryflow quickstart --fix
```

The command runs `doctor`, reports whether the local runtime is ready, and prints safe next steps. It never contacts a target or hosted provider. `--fix` only creates local artifact directories.
