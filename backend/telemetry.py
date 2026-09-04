"""Vendor-neutral endpoint/SIEM collection and exercise correlation.

Native collectors are read-only.  Correlation only accepts independent
``endpoint`` or ``siem`` events; receipt events never satisfy the gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .lab_exercises import TECHNIQUE_SCENARIOS


@dataclass(frozen=True)
class AcceptanceCriteria:
    technique_id: str
    scenario: str
    activity_event_types: tuple[str, ...]
    minimum_activity_events: int
    requirements: tuple[str, ...]
    limitation: str


_SCENARIO_ACTIVITY: Dict[str, tuple[str, ...]] = {
    "controlled_exception": ("process_error", "process_exit"),
    "mock_authentication": ("authentication_failure",),
    "password_cracking": ("process_start", "hash_operation"),
    "synthetic_input": ("process_start", "pipe_read"),
    "module_search": ("module_load", "file_create"),
    "web_content": ("http_request", "file_modify"),
    "loopback_transfer": ("network_connection", "network_transfer"),
    "loopback_proxy": ("network_connection", "network_relay"),
    "system_control": ("process_start", "process_stop"),
    "email_artifact": ("file_create", "email_parse"),
    "data_repository": ("database_query", "file_create"),
    "network_configuration": ("file_read", "configuration_parse"),
    "credential_material": ("credential_store_read", "file_read"),
    "content_obfuscation": ("archive_create", "encoding_operation"),
    "application_control": ("process_start", "file_create"),
    "persistence_configuration": ("configuration_change", "file_modify"),
    "supply_chain": ("integrity_check", "file_modify"),
    "cloud_identity": ("identity_change", "database_query"),
    "virtualization": ("inventory_read", "file_read"),
    "social_engineering": ("file_create", "content_inspection"),
    "osint_work_product": ("data_query", "file_read"),
    "infrastructure_work_product": ("manifest_create", "file_create"),
    "staging_work_product": ("file_create", "integrity_check"),
    "transaction_dry_run": ("transaction_validation",),
    "wireless_capture": ("capture_read", "file_create"),
}

_PROCESS_MARKER_TYPES = {"process_start", "process_creation", "process_exec", "provider_event"}


def _criteria(technique_id: str, scenario: str) -> AcceptanceCriteria:
    minimum = 5 if scenario == "mock_authentication" else 2 if scenario == "loopback_proxy" else 1
    return AcceptanceCriteria(
        technique_id=technique_id,
        scenario=scenario,
        activity_event_types=_SCENARIO_ACTIVITY[scenario],
        minimum_activity_events=minimum,
        requirements=(
            "Receipt SHA-256 is valid and the bounded exercise passed.",
            "An independent endpoint/SIEM process event contains the exact run_id and technique_id marker.",
            "Technique-relevant activity occurs on the marker host inside the receipt time window.",
        ),
        limitation="Confirms the bounded synthetic/analogue exercise telemetry, not harmful real-world behavior.",
    )


TECHNIQUE_ACCEPTANCE: Dict[str, AcceptanceCriteria] = {
    technique_id: _criteria(technique_id, scenario)
    for technique_id, scenario in TECHNIQUE_SCENARIOS.items()
}


def acceptance_record(technique_id: str) -> Dict[str, Any]:
    """Return one JSON-safe, technique-specific acceptance contract."""
    try:
        return asdict(TECHNIQUE_ACCEPTANCE[technique_id])
    except KeyError as exc:
        raise KeyError(f"no telemetry acceptance criteria for {technique_id}") from exc


def _time(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        seconds = float(value) / 1_000_000 if float(value) > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, timezone.utc)
    if not isinstance(value, str):
        raise ValueError("telemetry event has no ISO-8601 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def verify_receipt(receipt: Mapping[str, Any]) -> bool:
    digest = receipt.get("receipt_sha256")
    if not isinstance(digest, str):
        return False
    unsigned = dict(receipt)
    unsigned.pop("receipt_sha256", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest() == digest.lower()


def normalize_event(raw: Mapping[str, Any], default_source: str = "siem") -> Dict[str, Any]:
    timestamp = (
        raw.get("timestamp") or raw.get("@timestamp") or raw.get("time")
        or raw.get("TimeCreated") or raw.get("__REALTIME_TIMESTAMP")
    )
    message = raw.get("message") or raw.get("Message") or json.dumps(raw, sort_keys=True, default=str)
    source = str(raw.get("source") or default_source).lower()
    if source not in {"endpoint", "siem"}:
        raise ValueError("telemetry source must be endpoint or siem")
    return {
        "timestamp": _time(timestamp).isoformat(),
        "source": source,
        "event_id": str(raw.get("event_id") or raw.get("EventId") or raw.get("id") or "unidentified"),
        "host": str(raw.get("host") or raw.get("Computer") or raw.get("_HOSTNAME") or "unknown"),
        "event_type": str(raw.get("event_type") or raw.get("type") or "provider_event").lower(),
        "message": str(message),
        "run_id": str(raw.get("run_id") or ""),
        "technique_id": str(raw.get("technique_id") or ""),
        "count": max(1, int(raw.get("count", 1))),
    }


def read_events(paths: Sequence[Path]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        try:
            value = json.loads(text)
            if isinstance(value, list):
                rows = value
            elif isinstance(value, dict):
                rows = value.get("events", [value])
            else:
                raise ValueError(f"{path} must contain JSON objects")
        except json.JSONDecodeError:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise ValueError(f"{path} must contain a JSON event array or JSON Lines objects")
        events.extend(normalize_event(row) for row in rows)
    return events


def correlate(receipt: Mapping[str, Any], events: Iterable[Mapping[str, Any]], skew_seconds: int = 30) -> Dict[str, Any]:
    technique_id = str(receipt.get("technique_id", ""))
    criteria = TECHNIQUE_ACCEPTANCE.get(technique_id)
    if criteria is None:
        raise ValueError(f"no telemetry acceptance criteria for {technique_id!r}")
    digest_valid = verify_receipt(receipt)
    start = _time(receipt.get("started_at")) - timedelta(seconds=skew_seconds)
    end = _time(receipt.get("completed_at")) + timedelta(seconds=skew_seconds)
    normalized = [normalize_event(event) for event in events]
    window = [event for event in normalized if start <= _time(event["timestamp"]) <= end]
    run_id = str(receipt.get("run_id", ""))
    markers = [
        event for event in window
        if event["event_type"] in _PROCESS_MARKER_TYPES
        if (event["run_id"] == run_id or run_id in event["message"])
        and (event["technique_id"] == technique_id or technique_id in event["message"])
    ]
    marker_hosts = {event["host"] for event in markers if event["host"] != "unknown"}
    activities = [
        event for event in window
        if event["event_type"] in criteria.activity_event_types
        and event["host"] in marker_hosts
        and event not in markers
    ]
    activity_count = sum(event["count"] for event in activities)
    passed = bool(
        digest_valid
        and receipt.get("status") == "passed"
        and markers
        and marker_hosts
        and activity_count >= criteria.minimum_activity_events
    )
    references = sorted({f"{event['source']}:{event['event_id']}" for event in markers + activities})
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "technique_id": technique_id,
        "passed": passed,
        "receipt_digest_valid": digest_valid,
        "marker_events": len(markers),
        "activity_events": activity_count,
        "minimum_activity_events": criteria.minimum_activity_events,
        "matched_activity_types": sorted({event["event_type"] for event in activities}),
        "telemetry_refs": references,
        "criteria": asdict(criteria),
    }


def collect_native(platform_name: str, started_at: str, completed_at: str) -> List[Dict[str, Any]]:
    """Collect read-only OS log records for the receipt window."""
    system = platform_name.lower()
    if system == "auto":
        system = {"windows": "windows", "darwin": "macos"}.get(platform.system().lower(), "linux")
    if system == "windows":
        script = (
            f"$s=[datetime]'{started_at}';$e=[datetime]'{completed_at}';"
            "$logs='System','Application','Security','Microsoft-Windows-Sysmon/Operational';"
            "foreach($l in $logs){try{Get-WinEvent -FilterHashtable @{LogName=$l;StartTime=$s;EndTime=$e} "
            "-ErrorAction Stop|ForEach-Object{@{timestamp=$_.TimeCreated.ToUniversalTime().ToString('o');"
            "source='endpoint';event_id=$_.RecordId;host=$_.MachineName;event_type='provider_event';"
            "message=$_.Message}|ConvertTo-Json -Compress}}catch{}}"
        )
        command = ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]
    elif system == "macos":
        command = ["log", "show", "--start", started_at, "--end", completed_at, "--style", "json"]
    elif system == "linux":
        command = ["journalctl", "--since", started_at, "--until", completed_at, "--output", "json", "--no-pager"]
    else:
        raise ValueError("platform must be auto, windows, linux, or macos")
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"native collector exited {result.returncode}")
    try:
        document = json.loads(result.stdout)
        rows = document if isinstance(document, list) else [document]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return [normalize_event(row, default_source="endpoint") for row in rows]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect and correlate independent exercise telemetry")
    subparsers = parser.add_subparsers(dest="action", required=True)
    criteria_parser = subparsers.add_parser("criteria")
    criteria_parser.add_argument("technique_id", nargs="?")
    correlate_parser = subparsers.add_parser("correlate")
    correlate_parser.add_argument("--receipt", type=Path, required=True)
    correlate_parser.add_argument("--telemetry", type=Path, action="append", required=True)
    collect_parser = subparsers.add_parser("collect")
    collect_parser.add_argument("--receipt", type=Path, required=True)
    collect_parser.add_argument("--platform", choices=("auto", "windows", "linux", "macos"), default="auto")
    collect_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == "criteria":
        selected = TECHNIQUE_ACCEPTANCE if args.technique_id is None else {args.technique_id: TECHNIQUE_ACCEPTANCE[args.technique_id]}
        print(json.dumps({key: asdict(value) for key, value in selected.items()}, indent=2, sort_keys=True))
        return 0
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    if args.action == "collect":
        rows = collect_native(args.platform, receipt["started_at"], receipt["completed_at"])
        args.output.write_text(json.dumps({"events": rows}, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"events_collected": len(rows), "output": str(args.output)}))
        return 0
    result = correlate(receipt, read_events(args.telemetry))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
