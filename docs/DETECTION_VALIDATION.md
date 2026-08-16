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

### Normalized telemetry schema

Each normalized JSONL record uses the `ADVERSARYFLOW-TELEMETRY-1` schema. The required correlation fields are `run_id`, `host_id`, and `ability_id`. Records may also contain `technique_id`, `timestamp`, `user`, `process_id`, `process_name`, `event_id`, `detection_id`, `observed`, and `detected`. Vendor normalization accepts these source-specific aliases:

| Source | Host | Timestamp | Event ID | Detection ID |
|---|---|---|---|---|
| `generic` | `host_id` | `timestamp` | `event_id` | `detection_id` |
| `sentinel` | `host_id`, `Computer`, `DeviceName` | `timestamp`, `TimeGenerated` | `event_id`, `EventId` | `detection_id`, `SystemAlertId`, `AlertName` |
| `defender` | `host_id`, `DeviceName`, `DeviceId` | `timestamp`, `Timestamp` | `event_id`, `ReportId` | `detection_id`, `AlertId`, `Title` |
| `splunk` | `host_id`, `host`, `dest` | `timestamp`, `_time` | `event_id` | `detection_id`, `rule_id`, `savedsearch_name` |
| `elastic` | `host_id`, `host.name`, `agent.id` | `timestamp`, `@timestamp` | `event_id`, `event.id`, `_id` | `detection_id`, `kibana.alert.rule.uuid`, `rule.id` |
| `crowdstrike` | `host_id`, `hostname`, `aid` | `timestamp` | `event_id`, `event_simpleName`, `id` | `detection_id`, `detect_id` |

Correlation is bounded to a window of 1 through 86,400 seconds; the CLI default is 300 seconds. A record matches an execution only when its run, host, and ability identifiers match, and when both timestamps are present they are within the selected window. Sensor preflight separately requires run/host/ability correlation coverage and reports source, clock, agent, host, and correlation-field checks.

## Detection mappings, gaps, and retests

`adversaryflow detection export` writes defensive Sigma, Sentinel KQL, Splunk SPL, and Elastic EQL validation templates. The templates retain placeholders and are never deployed automatically; map them to organization-owned schemas and reviewed vendor rule IDs.

After assessment, run `adversaryflow campaign retest --campaign-id campaign-...`. The command returns the source run, gap-report path and SHA-256, the new immutable campaign ID, and the `retest.json` provenance artifact. The retest contains only unresolved cataloged abilities and still requires the normal RoE approval. Its generated report renders the source campaign/run relationship and gap-report hash.

Use `adversaryflow coverage` or the Manager coverage dashboard to review actor → technique → behavior → telemetry → detection → retest evidence.
