"""Independent EDR/SIEM observation correlation for completed local runs."""

import json
from pathlib import Path
from typing import Any


def load_telemetry_records(path: str | Path) -> tuple[dict[str, Any], ...]:
    records = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Telemetry JSONL line {line_number} is invalid: {exc.msg}") from exc
        for field in ("run_id", "host_id", "ability_id"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                raise ValueError(f"Telemetry JSONL line {line_number} requires {field}")
        if not isinstance(record.get("observed"), bool) or not isinstance(record.get("detected"), bool):
            raise ValueError(f"Telemetry JSONL line {line_number} requires boolean observed and detected fields")
        if record["detected"] and not record["observed"]:
            raise ValueError(f"Telemetry JSONL line {line_number} cannot be detected without being observed")
        records.append(record)
    return tuple(records)


def correlate_events(events: list[dict[str, Any]], run_id: str, records: tuple[dict[str, Any], ...] | None) -> dict[str, Any]:
    results = []
    for event in events:
        matches = [] if records is None else [record for record in records if record["run_id"] == run_id and record["host_id"] == event.get("host_id") and record["ability_id"] == event.get("ability_id")]
        if records is None:
            telemetry_status = "not-configured"
        elif any(record["detected"] for record in matches):
            telemetry_status = "detected"
        elif any(record["observed"] for record in matches):
            telemetry_status = "observed"
        else:
            telemetry_status = "missing"
        behavior_success = bool(event.get("behavior_success"))
        cleanup_status = str(event.get("cleanup_status", "not-required"))
        if not behavior_success:
            outcome = "behavior_failed"
        elif cleanup_status not in {"verified", "not-required"}:
            outcome = "cleanup_failed"
        elif telemetry_status in {"not-configured", "missing"}:
            outcome = "behavior_succeeded_telemetry_missing"
        elif telemetry_status == "observed":
            outcome = "telemetry_observed_no_detection"
        else:
            outcome = "detection_fired"
        results.append({
            "ability_id": event.get("ability_id"), "technique_id": event.get("technique_id"),
            "host_id": event.get("host_id"), "behavior_success": behavior_success,
            "cleanup_status": cleanup_status, "telemetry_status": telemetry_status, "outcome": outcome,
            "detection_ids": sorted({str(record["detection_id"]) for record in matches if record.get("detection_id")}),
            "event_ids": sorted({str(record["event_id"]) for record in matches if record.get("event_id")}),
        })
    gaps = [{"ability_id": result["ability_id"], "technique_id": result["technique_id"], "status": result["outcome"]} for result in results if result["outcome"] != "detection_fired"]
    return {
        "run_id": run_id, "behavior_success": bool(results) and all(item["behavior_success"] for item in results),
        "behavior_succeeded": sum(item["behavior_success"] for item in results),
        "telemetry_expected": len(results), "telemetry_observed": sum(item["telemetry_status"] in {"observed", "detected"} for item in results),
        "detections_fired": sum(item["telemetry_status"] == "detected" for item in results),
        "detection_gap_count": len(gaps), "telemetry_configured": records is not None,
        "results": results, "gaps": gaps,
        "assessment": "Behavior, external telemetry observation, detection, and cleanup are evaluated independently.",
    }
