"""Offline EDR/SIEM normalization, readiness, and run correlation."""

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TELEMETRY_SCHEMA = "ADVERSARYFLOW-TELEMETRY-1"
SUPPORTED_SOURCES = {"generic", "sentinel", "defender", "splunk", "elastic", "crowdstrike"}


def _nested(record: dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _first(record: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested(record, path)
        if value not in (None, ""):
            return value
    return None


def _load_export(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(value, list):
        records = value
    elif isinstance(value, dict):
        records = _first(value, "value", "results", "events", "hits.hits")
        if records is None:
            records = [value]
    else:
        raise ValueError("Telemetry export must contain a JSON object, array, or JSONL records")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError("Telemetry export records must be JSON objects")
    return records


def _source_fields(source: str) -> dict[str, tuple[str, ...]]:
    common = {
        "run_id": ("run_id", "adversaryflow_run_id", "labels.adversaryflow_run_id", "AdditionalFields.adversaryflow_run_id"),
        "ability_id": ("ability_id", "adversaryflow_ability_id", "labels.adversaryflow_ability_id", "AdditionalFields.adversaryflow_ability_id"),
        "technique_id": ("technique_id", "TechniqueId", "threat.technique.id", "attack_technique"),
        "user": ("user", "AccountName", "InitiatingProcessAccountName", "user.name"),
        "process_id": ("process_id", "ProcessId", "InitiatingProcessId", "process.pid"),
        "process_name": ("process_name", "FileName", "InitiatingProcessFileName", "process.name"),
    }
    variants = {
        "sentinel": {"host_id": ("host_id", "Computer", "DeviceName"), "timestamp": ("timestamp", "TimeGenerated"), "event_id": ("event_id", "EventId"), "detection_id": ("detection_id", "SystemAlertId", "AlertName")},
        "defender": {"host_id": ("host_id", "DeviceName", "DeviceId"), "timestamp": ("timestamp", "Timestamp"), "event_id": ("event_id", "ReportId"), "detection_id": ("detection_id", "AlertId", "Title")},
        "splunk": {"host_id": ("host_id", "host", "dest"), "timestamp": ("timestamp", "_time"), "event_id": ("event_id",), "detection_id": ("detection_id", "rule_id", "savedsearch_name")},
        "elastic": {"host_id": ("host_id", "host.name", "agent.id"), "timestamp": ("timestamp", "@timestamp"), "event_id": ("event_id", "event.id", "_id"), "detection_id": ("detection_id", "kibana.alert.rule.uuid", "rule.id")},
        "crowdstrike": {"host_id": ("host_id", "hostname", "aid"), "timestamp": ("timestamp",), "event_id": ("event_id", "event_simpleName", "id"), "detection_id": ("detection_id", "detect_id")},
        "generic": {"host_id": ("host_id",), "timestamp": ("timestamp",), "event_id": ("event_id",), "detection_id": ("detection_id",)},
    }
    return {**common, **variants[source]}


def normalize_export(source: str, path: str | Path) -> tuple[dict[str, Any], ...]:
    """Normalize an offline vendor export without contacting the vendor."""
    source = source.casefold()
    if source not in SUPPORTED_SOURCES:
        raise ValueError(f"Unsupported telemetry source: {source}")
    fields = _source_fields(source)
    normalized = []
    for index, raw in enumerate(_load_export(path), 1):
        if source == "elastic" and isinstance(raw.get("_source"), dict):
            raw = {**raw, **raw["_source"]}
        record = {name: _first(raw, *paths) for name, paths in fields.items()}
        for required in ("run_id", "host_id", "ability_id"):
            if not isinstance(record.get(required), str) or not str(record[required]).strip():
                raise ValueError(f"{source} export record {index} requires a mapped {required}")
        detected_value = _first(raw, "detected", "is_detection", "alerted")
        detected = bool(record.get("detection_id")) if detected_value is None else detected_value is True
        observed_value = _first(raw, "observed")
        observed = True if observed_value is None else observed_value is True
        if detected:
            observed = True
        normalized.append({
            "schema": TELEMETRY_SCHEMA, "source": source,
            **{name: str(value) for name, value in record.items() if value not in (None, "")},
            "observed": observed, "detected": detected,
            "normalized_at": datetime.now(timezone.utc).isoformat(), "raw_record_index": index,
        })
    return tuple(normalized)


def write_normalized(records: tuple[dict[str, Any], ...], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(item, sort_keys=True) for item in records) + ("\n" if records else ""), encoding="utf-8")
    return path


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


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)
    except ValueError:
        return None


def _matches(event: dict[str, Any], record: dict[str, Any], run_id: str, window_seconds: int) -> bool:
    if record["run_id"] != run_id or record["host_id"] != event.get("host_id") or record["ability_id"] != event.get("ability_id"):
        return False
    for field in ("user", "process_id", "process_name"):
        if event.get(field) and record.get(field) and str(event[field]).casefold() != str(record[field]).casefold():
            return False
    event_time, record_time = _timestamp(event.get("executed_at")), _timestamp(record.get("timestamp"))
    return not (event_time and record_time) or abs((record_time - event_time).total_seconds()) <= window_seconds


def sensor_preflight(events: list[dict[str, Any]], run_id: str, records: tuple[dict[str, Any], ...]) -> dict[str, Any]:
    expected_sources = sorted({str(item.get("category", "endpoint")) for event in events for item in event.get("telemetry", [])})
    supplied_sources = sorted({str(record.get("source", "generic")) for record in records})
    run_records = [record for record in records if record["run_id"] == run_id]
    hosts = sorted({str(event.get("host_id")) for event in events if event.get("host_id")})
    timestamped = sum(_timestamp(record.get("timestamp")) is not None for record in run_records)
    checks = [
        {"name": "run-records", "passed": bool(run_records), "detail": f"{len(run_records)} normalized records match the run."},
        {"name": "host-coverage", "passed": all(any(record["host_id"] == host for record in run_records) for host in hosts), "detail": f"Expected hosts: {', '.join(hosts) or 'none'}."},
        {"name": "clock-fields", "passed": not run_records or timestamped == len(run_records), "detail": f"{timestamped} of {len(run_records)} matching records have parseable timestamps."},
        {"name": "correlation-fields", "passed": all(record.get("ability_id") for record in run_records), "detail": "Run, host, and ability identifiers are required."},
    ]
    return {
        "schema": "ADVERSARYFLOW-SENSOR-PREFLIGHT-1", "run_id": run_id,
        "ready": all(check["passed"] for check in checks), "checks": checks,
        "expected_telemetry_categories": expected_sources, "supplied_sources": supplied_sources,
        "agent_health": "reported" if any(record.get("agent_health") for record in run_records) else "not-reported",
        "boundary": "Read-only analysis of an offline export; no sensor or vendor API was queried.",
    }


def planned_sensor_preflight(expected_categories: set[str], target: str, manifest_path: str | Path) -> dict[str, Any]:
    """Validate a read-only sensor-health snapshot before local execution."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("Sensor manifest must be a JSON object")
    sources = {str(item) for item in manifest.get("available_sources", []) if isinstance(item, str)}
    agents = manifest.get("agents", [])
    if not isinstance(agents, list) or any(not isinstance(item, dict) for item in agents):
        raise ValueError("Sensor manifest agents must be a list of objects")
    unhealthy = [str(item.get("name", item.get("source", "unknown"))) for item in agents if item.get("health") != "healthy"]
    missing = sorted(expected_categories - sources)
    checks = [
        {"name": "target", "passed": manifest.get("host_id") == target, "detail": f"Expected sensor snapshot for {target}."},
        {"name": "required-sources", "passed": not missing, "detail": "Missing: " + (", ".join(missing) if missing else "none")},
        {"name": "clock-sync", "passed": manifest.get("clock_synchronized") is True, "detail": "The snapshot must explicitly report synchronized time."},
        {"name": "agent-health", "passed": bool(agents) and not unhealthy, "detail": "Unhealthy: " + (", ".join(unhealthy) if unhealthy else "none")},
    ]
    return {
        "schema": "ADVERSARYFLOW-PLANNED-SENSOR-PREFLIGHT-1", "target": target,
        "ready": all(item["passed"] for item in checks), "checks": checks,
        "expected_telemetry_categories": sorted(expected_categories), "available_sources": sorted(sources),
        "boundary": "Validated a supplied read-only health snapshot; no sensor or vendor API was queried.",
    }


def correlate_events(events: list[dict[str, Any]], run_id: str, records: tuple[dict[str, Any], ...] | None, window_seconds: int = 300) -> dict[str, Any]:
    if not 1 <= window_seconds <= 86400:
        raise ValueError("correlation window must be between 1 and 86400 seconds")
    results = []
    for event in events:
        matches = [] if records is None else [record for record in records if _matches(event, record, run_id, window_seconds)]
        if records is None:
            telemetry_status = "not-configured"
        elif any(record.get("ambiguous") is True for record in matches):
            telemetry_status = "ambiguous"
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
        elif telemetry_status == "ambiguous":
            outcome = "telemetry_correlation_ambiguous"
        elif telemetry_status == "observed":
            outcome = "telemetry_observed_no_detection"
        else:
            outcome = "detection_fired"
        results.append({
            "ability_id": event.get("ability_id"), "technique_id": event.get("technique_id"),
            "host_id": event.get("host_id"), "behavior_success": behavior_success,
            "cleanup_status": cleanup_status, "telemetry_status": telemetry_status, "outcome": outcome,
            "correlation": {"matched_records": len(matches), "window_seconds": window_seconds, "fields": ["run_id", "host_id", "ability_id", "timestamp", "user", "process_id", "process_name"]},
            "detection_ids": sorted({str(record["detection_id"]) for record in matches if record.get("detection_id")}),
            "event_ids": sorted({str(record["event_id"]) for record in matches if record.get("event_id")}),
        })
    gaps = [{"ability_id": result["ability_id"], "technique_id": result["technique_id"], "status": result["outcome"]} for result in results if result["outcome"] != "detection_fired"]
    return {
        "run_id": run_id, "behavior_success": bool(results) and all(item["behavior_success"] for item in results),
        "behavior_succeeded": sum(item["behavior_success"] for item in results),
        "telemetry_expected": len(results), "telemetry_observed": sum(item["telemetry_status"] in {"observed", "detected"} for item in results),
        "detections_fired": sum(item["telemetry_status"] == "detected" for item in results),
        "ambiguous_correlations": sum(item["telemetry_status"] == "ambiguous" for item in results),
        "detection_gap_count": len(gaps), "telemetry_configured": records is not None,
        "results": results, "gaps": gaps,
        "assessment": "Behavior, external telemetry observation, detection, and cleanup are evaluated independently.",
    }


def export_assessment(report: dict[str, Any], output: str | Path, format_name: str) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    if format_name == "json":
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    elif format_name == "csv":
        fields = ("run_id", "ability_id", "technique_id", "host_id", "behavior_success", "cleanup_status", "telemetry_status", "outcome")
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for result in report.get("results", []):
                writer.writerow({**{field: result.get(field) for field in fields}, "run_id": report.get("run_id")})
    else:
        raise ValueError("assessment format must be json or csv")
    return path
