# Curated behavioral abilities

Curated abilities execute fixed benign host behavior through the `local-behavioral` adapter. Intelligence-generated synthetic markers are planning coverage only and cannot pass this adapter's preflight.

## Current platform catalogs

The packaged `curated-windows` catalog includes five read-only behaviors: current identity (`T1033`), system information (`T1082`), network configuration (`T1016`), process discovery (`T1057`), and local-group discovery (`T1069.001`). The executor maps each catalog action name to a code-owned command and argument list. Catalog files cannot provide commands or scripts.

The packaged `curated-linux` and `curated-macos` catalogs each include three fixed read-only behaviors: current identity (`T1033`), system information (`T1082`), and process discovery (`T1057`). They use only code-owned argument lists, bounded output, and no network access.

Run the reviewed catalog:

```powershell
adversaryflow adapter status --name local-behavioral --catalog curated-windows
adversaryflow campaign --actor "Curated Windows Baseline" --platform windows --catalog curated-windows --objective "validate endpoint discovery telemetry"
adversaryflow campaign --campaign-id campaign-... --catalog curated-windows --approve --approver manager@example.test --adapter local-behavioral
```

Substitute `curated-linux --platform linux` or `curated-macos --platform macos` on the matching local workstation.

The completed run initially reports behavior independently from telemetry. Export EDR/SIEM results to JSONL and assess them later:

```json
{"run_id":"run-...","host_id":"local-lab","ability_id":"ability-windows-current-identity","observed":true,"detected":true,"detection_id":"rule-123","event_id":"4688"}
```

```powershell
adversaryflow campaign assess --campaign-id campaign-... --telemetry-file telemetry.jsonl
```

Vendor exports can first be normalized offline with `adversaryflow telemetry normalize`. Run `telemetry preflight` to check correlation identifiers and timestamps before assessment.

## Expanding the catalog

Every new behavioral ability must include:

1. An exact ATT&CK technique or sub-technique ID and authoritative reference.
2. A fixed action name registered in `_FIXED_BEHAVIOR_ACTIONS`; operator-supplied commands are prohibited.
3. A benign implementation limited to read-only state or run-owned artifacts.
4. A timeout of at most 60 seconds, bounded output, expected telemetry, and an explicit cleanup contract.
5. Unit tests for success, missing prerequisites, timeout, non-zero exit, preflight rejection, and cleanup where applicable.
6. A local integration run demonstrating behavior evidence without claiming telemetry or detection.
7. Independent EDR/SIEM correlation keyed by exact run, host, and ability IDs.

Techniques requiring elevation or persistent system changes—such as actual Windows service creation—remain unsupported until a separate elevated-change policy, disposable-lab requirement, rollback verification, and explicit risk approval are implemented.
