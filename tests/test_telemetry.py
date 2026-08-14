import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from adversaryflow.adapters import AdapterRequest, LocalBehavioralAdapter, preflight_adapter
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import curated_windows_catalog_path, load_catalog
from adversaryflow.telemetry import correlate_events, load_telemetry_records


def _event(success=True, cleanup="not-required"):
    return {"ability_id": "ability-one", "technique_id": "T1033", "host_id": "local-lab", "behavior_success": success, "cleanup_status": cleanup}


def test_external_telemetry_correlation_keeps_outcomes_independent():
    records = (
        {"run_id": "run-one", "host_id": "local-lab", "ability_id": "ability-one", "observed": True, "detected": False, "event_id": "4688"},
    )
    observed = correlate_events([_event()], "run-one", records)
    assert observed["results"][0]["outcome"] == "telemetry_observed_no_detection"
    detected = correlate_events([_event()], "run-one", records + ({"run_id": "run-one", "host_id": "local-lab", "ability_id": "ability-one", "observed": True, "detected": True, "detection_id": "rule-1"},))
    assert detected["results"][0]["outcome"] == "detection_fired"
    assert detected["results"][0]["detection_ids"] == ["rule-1"]
    assert correlate_events([_event(False)], "run-one", records)["results"][0]["outcome"] == "behavior_failed"
    assert correlate_events([_event(cleanup="failed")], "run-one", records)["results"][0]["outcome"] == "cleanup_failed"


@pytest.mark.parametrize("line,message", [
    ("not-json", "invalid"),
    ('{"host_id":"h","ability_id":"a","observed":true,"detected":false}', "run_id"),
    ('{"run_id":"r","host_id":"h","ability_id":"a","observed":"yes","detected":false}', "boolean"),
    ('{"run_id":"r","host_id":"h","ability_id":"a","observed":false,"detected":true}', "cannot be detected"),
])
def test_telemetry_jsonl_validation_fails_closed(line, message):
    path = Path("artifacts") / f"telemetry-invalid-{uuid4()}.jsonl"
    path.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        load_telemetry_records(path)


def test_behavioral_adapter_executes_only_registered_fixed_action(monkeypatch):
    abilities = load_catalog("content/abilities/curated-windows.json")[:1]
    draft = OfflinePlanner().draft(CampaignRequest("baseline", "local-lab", "validate", "windows"), abilities)
    monkeypatch.setattr("adversaryflow.adapters.shutil.which", lambda command: f"C:/Windows/{command}")
    monkeypatch.setattr("adversaryflow.adapters.subprocess.run", lambda args, **kwargs: SimpleNamespace(returncode=0, stdout=b"identity", stderr=b""))
    request = AdapterRequest(draft, abilities, "run-one", work_root=str(Path("artifacts") / f"behavior-work-{uuid4()}"))
    adapter, preflight = preflight_adapter("local-behavioral", request)
    result = adapter.execute(request)
    assert preflight.adapter == "local-behavioral"
    assert result.events[0]["behavior_success"] is True
    assert result.events[0]["execution"] == "fixed-local-behavior"
    assert result.events[0]["stdout_bytes"] == 8


def test_behavioral_adapter_records_missing_executable_and_timeout(monkeypatch):
    abilities = load_catalog("content/abilities/curated-windows.json")[:1]
    draft = OfflinePlanner().draft(CampaignRequest("baseline", "local-lab", "validate", "windows"), abilities)
    request = AdapterRequest(draft, abilities, "run-one", work_root=str(Path("artifacts") / f"behavior-work-{uuid4()}"))
    monkeypatch.setattr("adversaryflow.adapters.shutil.which", lambda _command: None)
    missing = LocalBehavioralAdapter().execute(request).events[0]
    assert missing["behavior_success"] is False
    monkeypatch.setattr("adversaryflow.adapters.shutil.which", lambda command: command)
    monkeypatch.setattr("adversaryflow.adapters.subprocess.run", lambda *args, **kwargs: (_ for _ in ()).throw(__import__("subprocess").TimeoutExpired("whoami", 1)))
    timed_out = LocalBehavioralAdapter().execute(request).events[0]
    assert timed_out["failure"].endswith("timed out")


def test_behavioral_adapter_rejects_unregistered_or_missing_work_root():
    synthetic = load_catalog("content/abilities/catalog.json")[:1]
    draft = OfflinePlanner().draft(CampaignRequest("baseline", "local-lab", "validate", "linux"), synthetic)
    with pytest.raises(ValueError, match="registered fixed"):
        preflight_adapter("local-behavioral", AdapterRequest(draft, synthetic, "run-one", work_root=str(Path("artifacts") / f"behavior-work-{uuid4()}")))
    curated = load_catalog("content/abilities/curated-windows.json")[:1]
    curated_draft = OfflinePlanner().draft(CampaignRequest("baseline", "local-lab", "validate", "windows"), curated)
    with pytest.raises(ValueError, match="work root"):
        LocalBehavioralAdapter().execute(AdapterRequest(curated_draft, curated, "run-one"))


def test_packaged_curated_catalog_matches_source_catalog():
    source = json.loads(Path("content/abilities/curated-windows.json").read_text(encoding="utf-8"))
    packaged = json.loads(curated_windows_catalog_path().read_text(encoding="utf-8"))
    assert packaged == source
