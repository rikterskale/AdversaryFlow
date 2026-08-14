# Detection validation workflow

AdversaryFlow keeps behavior execution, telemetry observation, detection, cleanup, and retesting as independent outcomes. All vendor ingestion is based on operator-supplied offline exports; no connector queries or changes a production service.

## Pre-execution sensor gate

Create a read-only health snapshot from your approved lab operations process:

```json
{
  "host_id": "local-lab",
  "clock_synchronized": true,
  "available_sources": ["process", "file", "network"],
  "agents": [{"name": "lab-edr", "health": "healthy"}]
}
```

Validate it with `adversaryflow telemetry preflight --sensor-manifest sensors.json --catalog curated-windows`. Add `--sensor-manifest sensors.json` to the approved `campaign` command to make readiness a fail-closed execution gate.

## Normalize and correlate

```powershell
adversaryflow telemetry normalize --source defender --input defender-export.json --output normalized.jsonl
adversaryflow telemetry preflight --run-dir artifacts/runs/run-... --telemetry-file normalized.jsonl
adversaryflow campaign assess --campaign-id campaign-... --telemetry-file normalized.jsonl --window-seconds 300
adversaryflow telemetry export --run-dir artifacts/runs/run-... --format csv --output assessment.csv
```

Supported source names are `generic`, `sentinel`, `defender`, `splunk`, `elastic`, and `crowdstrike`. Correlation requires exact run, host, and ability identifiers and can additionally constrain timestamps, user, process ID, and process name.

## Detection mappings, gaps, and retests

`adversaryflow detection export` writes defensive Sigma, Sentinel KQL, Splunk SPL, and Elastic EQL validation templates. The templates retain placeholders and are never deployed automatically; map them to organization-owned schemas and reviewed vendor rule IDs.

After assessment, run `adversaryflow campaign retest --campaign-id campaign-...`. The new campaign is an immutable review draft containing only unresolved cataloged abilities and provenance linking it to the source campaign and run. It still requires the normal RoE approval.

Use `adversaryflow coverage` or the Manager coverage dashboard to review actor → technique → behavior → telemetry → detection → retest evidence.
