# Examples

These examples use the packaged defaults. All examples remain within the local simulation boundary except `plan`, which retrieves the MITRE ATT&CK Enterprise STIX bundle over HTTPS while producing a dry-run plan.

## Validate the local setup

```powershell
adversaryflow doctor --json
adversaryflow validate examples/roe.yaml
```

## Plan and draft

```powershell
adversaryflow plan --roe examples/roe.yaml --actor "APT29" --technique T1059.001
adversaryflow draft --roe examples/roe.yaml --actor "APT29" --objective "validate endpoint process visibility"
```

`plan` is dry-run planning; `draft` uses the offline planner and validates the resulting draft against the RoE and catalog.

## Enrich actor coverage

```powershell
adversaryflow intel-sync --actor "APT29" --platform windows --output artifacts/intel/apt29
adversaryflow intel-sync --actor "APT29" --platform windows --output artifacts/intel/apt29 --mitre-only
```

`intel-sync` writes a reviewable synthetic-only coverage plan beneath the selected output directory. `--mitre-only` skips the CTID library lookup. Imported commands, payloads, and setup instructions are not retained.

## Normalize and export telemetry

```powershell
adversaryflow telemetry normalize --source defender --input defender-export.json --output normalized.jsonl
adversaryflow telemetry preflight --run-dir artifacts/runs/run-... --telemetry-file normalized.jsonl
adversaryflow campaign assess --campaign-id campaign-... --telemetry-file normalized.jsonl
adversaryflow telemetry export --run-dir artifacts/runs/run-... --format csv --output assessment.csv
```

These commands use offline files. They do not query a sensor or deploy a detection rule.

## Detection mappings, coverage, and retesting

```powershell
adversaryflow detection export --output artifacts/detection-mappings
adversaryflow coverage --campaign-root artifacts/campaigns
adversaryflow campaign retest --campaign-id campaign-...
```

Detection export produces validation templates only. Coverage is read-only. Retesting creates a new immutable review draft from recorded unresolved gaps and still requires approval.

## Reviewable campaign

```powershell
adversaryflow campaign --actor "APT29" --objective "validate endpoint process visibility"
adversaryflow campaign inspect --campaign-id campaign-...
```

After scope and schedule review, only the approver named in the RoE may authorize local synthetic emulation:

```powershell
adversaryflow campaign --campaign-id campaign-... --approve --approver "manager@example.test"
```

## Recover from a provider failure

```powershell
adversaryflow provider diagnose
adversaryflow campaign --actor "APT29" --objective "validate endpoint process visibility" --fallback-offline
```

## Record a decision

```powershell
adversaryflow campaign reject --campaign-id campaign-... --approver "manager@example.test" --reason "Not scheduled"
adversaryflow campaign cancel --campaign-id campaign-... --reason "Operator requested stop"
```

## Guided workspace

```powershell
adversaryflow guide --interactive
adversaryflow manager --open
```

The manager is loopback-only. It can approve and run a reviewed campaign only through the fixed `local-synthetic` adapter after the named RoE approver enters the exact confirmation; `local-behavioral` and `idpt-local` execution remain CLI-only.
## First-run readiness

```bash
adversaryflow quickstart
adversaryflow quickstart --fix
```

The command runs the safe local readiness checks and prints the canonical next steps. It does not contact a provider or external target.
