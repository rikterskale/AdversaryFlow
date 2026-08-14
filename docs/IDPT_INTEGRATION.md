# IDPT local integration

The `idpt-local` adapter delegates one reviewed Windows collection scenario to IDPT Emulation and imports its verified evidence. AdversaryFlow remains the campaign orchestrator and approval system; IDPT remains the typed local executor and evidence producer.

## Trust boundary

The adapter accepts no command, script, scenario, ability ID, commit, or network destination from a campaign. It supports only IDPT scenario `scenario--windows-safe-collection-flow` at reviewed commit `dcdac0f3e82469a95975a170bc201b06e164b7b6` and content version `2.0.0`.

Before Node.js is invoked, AdversaryFlow verifies:

1. `ADVERSARYFLOW_IDPT_ROOT` contains `src/cli.mjs`.
2. Git `HEAD` equals the reviewed commit.
3. No tracked IDPT file is modified.
4. IDPT's own `validate` command accepts its content manifest.
5. The generated plan contains exactly the five mapped abilities, expected techniques, approved host, and fixed scenario.
6. IDPT's evidence verifier accepts the completed run.

Untracked IDPT output is permitted because IDPT writes run artifacts beneath its checkout by default. The integration itself always supplies an AdversaryFlow run-owned output directory.

## Setup

```powershell
git clone https://github.com/rikterskale/IDPT-Emulation.git C:\Tools\IDPT-Emulation
git -C C:\Tools\IDPT-Emulation checkout dcdac0f3e82469a95975a170bc201b06e164b7b6
$env:ADVERSARYFLOW_IDPT_ROOT = "C:\Tools\IDPT-Emulation"
adversaryflow adapter status --name idpt-local --catalog idpt-windows-collection
```

Node.js 20 or newer and Git must be available on `PATH`.

## Run the reviewed scenario

Create the draft first:

```powershell
adversaryflow campaign --actor "IDPT Windows Collection Baseline" --platform windows --catalog idpt-windows-collection --objective "validate benign collection telemetry"
```

Review the returned ability set and campaign ID. Then resume the exact draft with the RoE-named approver:

```powershell
adversaryflow campaign --campaign-id campaign-... --catalog idpt-windows-collection --approve --approver manager@example.test --adapter idpt-local
```

AdversaryFlow creates a short-lived derived IDPT RoE bound to the generated IDPT plan ID, canonical SHA-256, host, scenario, technique set, and existing AdversaryFlow approval ID. The IDPT checkout and all nested output remain local.

## Evidence and telemetry

The AdversaryFlow run contains `work/idpt/integration.json`, the generated host inventory and derived IDPT RoE, IDPT plan exports, `run.json`, per-action evidence, HTML report, and evidence manifest. Imported AdversaryFlow events retain both identifier sets.

IDPT behavior success is imported independently from telemetry. AdversaryFlow initially reports telemetry as not configured. Use `campaign assess --telemetry-file` with AdversaryFlow run, host, and ability IDs after exporting matching EDR/SIEM observations.

Remote dispatch, arbitrary IDPT scenarios, arbitrary commands, dirty checkouts, unreviewed commits, and production endpoints are not supported.
