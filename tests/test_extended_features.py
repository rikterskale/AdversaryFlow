import json
import sys
from pathlib import Path

import pytest

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow import cli
from adversaryflow.cli import load_roe
from adversaryflow.coverage import coverage_dashboard
from adversaryflow.detection_mappings import mappings, write_bundle
from adversaryflow.emulation import (
    curated_linux_catalog_path,
    curated_macos_catalog_path,
    load_catalog,
)
from adversaryflow.idpt_registry import resolve_scenario, scenarios
from adversaryflow import idpt_registry
from adversaryflow.retest import create_gap_retest
from adversaryflow.telemetry import (
    correlate_events,
    export_assessment,
    load_telemetry_records,
    normalize_export,
    planned_sensor_preflight,
    sensor_preflight,
    write_normalized,
)
from adversaryflow.workflow import campaign_integrity_hashes, save_campaign_draft


@pytest.mark.parametrize(
    ("source", "record"),
    [
        ("generic", {"run_id": "run-one", "host_id": "host-one", "ability_id": "ability-one", "timestamp": "2026-08-14T12:00:00Z"}),
        ("sentinel", {"adversaryflow_run_id": "run-one", "Computer": "host-one", "adversaryflow_ability_id": "ability-one", "TimeGenerated": "2026-08-14T12:00:00Z", "SystemAlertId": "alert-one"}),
        ("defender", {"adversaryflow_run_id": "run-one", "DeviceName": "host-one", "adversaryflow_ability_id": "ability-one", "Timestamp": "2026-08-14T12:00:00Z"}),
        ("splunk", {"adversaryflow_run_id": "run-one", "host": "host-one", "adversaryflow_ability_id": "ability-one", "_time": "2026-08-14T12:00:00Z"}),
        ("elastic", {"_source": {"labels": {"adversaryflow_run_id": "run-one", "adversaryflow_ability_id": "ability-one"}, "host": {"name": "host-one"}, "@timestamp": "2026-08-14T12:00:00Z"}}),
        ("crowdstrike", {"adversaryflow_run_id": "run-one", "hostname": "host-one", "adversaryflow_ability_id": "ability-one", "timestamp": "2026-08-14T12:00:00Z"}),
    ],
)
def test_offline_vendor_exports_normalize_to_one_schema(tmp_path, source, record):
    export = tmp_path / f"{source}.json"
    export.write_text(json.dumps([record]), encoding="utf-8")
    normalized = normalize_export(source, export)
    assert normalized[0]["source"] == source
    assert normalized[0]["run_id"] == "run-one"
    output = write_normalized(normalized, tmp_path / f"{source}.jsonl")
    assert load_telemetry_records(output) == normalized


def test_sensor_preflight_and_time_bounded_correlation():
    event = {"run_id": "run-one", "host_id": "host-one", "ability_id": "ability-one", "technique_id": "T1057", "behavior_success": True, "cleanup_status": "not-required", "executed_at": "2026-08-14T12:00:00Z", "telemetry": [{"category": "process"}]}
    record = {"run_id": "run-one", "host_id": "host-one", "ability_id": "ability-one", "observed": True, "detected": False, "source": "defender", "timestamp": "2026-08-14T12:00:10Z"}
    ready = sensor_preflight([event], "run-one", (record,))
    assert ready["ready"] is True
    assert correlate_events([event], "run-one", (record,), 30)["results"][0]["telemetry_status"] == "observed"
    late = {**record, "timestamp": "2026-08-14T12:10:00Z"}
    assert correlate_events([event], "run-one", (late,), 30)["results"][0]["telemetry_status"] == "missing"
    ambiguous = {**record, "ambiguous": True}
    assert correlate_events([event], "run-one", (ambiguous,), 30)["results"][0]["outcome"] == "telemetry_correlation_ambiguous"


def test_planned_sensor_snapshot_can_gate_execution(tmp_path):
    snapshot = tmp_path / "sensors.json"
    snapshot.write_text(json.dumps({"host_id": "local-lab", "clock_synchronized": True, "available_sources": ["process", "file"], "agents": [{"name": "edr", "health": "healthy"}]}), encoding="utf-8")
    assert planned_sensor_preflight({"process"}, "local-lab", snapshot)["ready"] is True
    failed = planned_sensor_preflight({"process", "network"}, "local-lab", snapshot)
    assert failed["ready"] is False
    assert next(item for item in failed["checks"] if item["name"] == "required-sources")["passed"] is False
    snapshot.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        planned_sensor_preflight({"process"}, "local-lab", snapshot)
    snapshot.write_text(json.dumps({"agents": ["invalid"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="list of objects"):
        planned_sensor_preflight({"process"}, "local-lab", snapshot)


def test_telemetry_formats_fail_closed_and_export_assessments(tmp_path):
    jsonl = tmp_path / "input.jsonl"
    jsonl.write_text('{"run_id":"run-one","host_id":"host","ability_id":"ability","observed":true,"detected":false}\n', encoding="utf-8")
    assert normalize_export("generic", jsonl)[0]["run_id"] == "run-one"
    wrapped = tmp_path / "wrapped.json"
    wrapped.write_text(json.dumps({"events": [{"run_id": "run-one", "host_id": "host", "ability_id": "ability"}]}), encoding="utf-8")
    assert len(normalize_export("generic", wrapped)) == 1
    single = tmp_path / "single.json"
    single.write_text(json.dumps({"run_id": "run-one", "host_id": "host", "ability_id": "ability"}), encoding="utf-8")
    assert len(normalize_export("generic", single)) == 1
    invalid = tmp_path / "invalid.json"
    invalid.write_text("42", encoding="utf-8")
    with pytest.raises(ValueError, match="object, array"):
        normalize_export("generic", invalid)
    invalid.write_text(json.dumps({"events": ["not-an-object"]}), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON objects"):
        normalize_export("generic", invalid)
    invalid.write_text(json.dumps([{"host_id": "host", "ability_id": "ability"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="mapped run_id"):
        normalize_export("generic", invalid)
    with pytest.raises(ValueError, match="Unsupported"):
        normalize_export("unknown", invalid)
    assert correlate_events([], "run-one", (), 300)["behavior_success"] is False
    with pytest.raises(ValueError, match="between 1"):
        correlate_events([], "run-one", (), 0)
    event = {"host_id": "host", "ability_id": "ability", "behavior_success": True, "executed_at": "not-a-time", "user": "alice"}
    record = {"run_id": "run-one", "host_id": "host", "ability_id": "ability", "observed": True, "detected": False, "timestamp": "also-bad", "user": "bob"}
    assert correlate_events([event], "run-one", (record,))["results"][0]["telemetry_status"] == "missing"
    report = {"run_id": "run-one", "results": [{"ability_id": "ability", "technique_id": "T1057", "host_id": "host", "behavior_success": True, "cleanup_status": "not-required", "telemetry_status": "observed", "outcome": "telemetry_observed_no_detection"}]}
    assert export_assessment(report, tmp_path / "report.json", "json").is_file()
    assert "ability" in export_assessment(report, tmp_path / "report.csv", "csv").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="json or csv"):
        export_assessment(report, tmp_path / "report.txt", "text")


def _completed_campaign(root: Path):
    roe = load_roe("examples/roe.yaml")
    abilities = load_catalog("content/abilities/catalog.json")
    draft = OfflinePlanner().draft(CampaignRequest("APT41", "local-lab", "validate telemetry", "linux"), abilities)
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    directory = save_campaign_draft(draft, integrity["plan_hash"], "offline", root, roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"])
    run = root / "runs" / "run-source"
    run.mkdir(parents=True)
    results = [{"ability_id": ability.id, "technique_id": ability.technique_id, "host_id": "local-lab", "behavior_success": True, "cleanup_status": "not-required", "telemetry_status": "missing", "outcome": "behavior_succeeded_telemetry_missing"} for ability in abilities if ability.id in draft.ability_ids]
    report = {"run_id": run.name, "results": results, "gaps": [{"ability_id": item["ability_id"], "technique_id": item["technique_id"], "status": item["outcome"]} for item in results]}
    (run / "telemetry-gap-report.json").write_text(json.dumps(report), encoding="utf-8")
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update({"status": "completed", "run_dir": str(run)})
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    return roe, abilities, directory


def test_gap_retest_is_immutable_and_coverage_is_traceable(tmp_path):
    root = tmp_path / "campaigns"
    roe, abilities, source = _completed_campaign(root)
    retest = create_gap_retest(root, source.name, roe, abilities)
    assert retest["retest_of"] == source.name
    retest_record = json.loads((root / retest["campaign_id"] / "retest.json").read_text(encoding="utf-8"))
    assert retest_record["source_campaign_id"] == source.name
    dashboard = coverage_dashboard(root)
    assert dashboard["summary"]["campaigns"] == 2
    assert dashboard["summary"]["gaps"] >= 1
    assert dashboard["flow"][-1] == "retest"


def test_gap_retest_rejects_resolved_source(tmp_path):
    root = tmp_path / "campaigns"
    roe, abilities, source = _completed_campaign(root)
    metadata = json.loads((source / "metadata.json").read_text(encoding="utf-8"))
    report_path = Path(metadata["run_dir"]) / "telemetry-gap-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8")); report["gaps"] = []
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="no unresolved"):
        create_gap_retest(root, source.name, roe, abilities)


def test_detection_templates_and_cross_platform_catalogs(tmp_path):
    linux = load_catalog(curated_linux_catalog_path())
    macos = load_catalog(curated_macos_catalog_path())
    assert {ability.platform for ability in linux} == {"linux"}
    assert {ability.platform for ability in macos} == {"macos"}
    mapped = mappings(linux)
    assert {"sigma", "sentinel_kql", "splunk_spl", "elastic_eql"} == set(mapped[0]["templates"])
    bundle = write_bundle(linux, tmp_path / "rules")
    assert bundle["mapping_count"] == len(linux)


def test_idpt_registry_resolves_exact_reviewed_scenario():
    registered = scenarios()
    assert registered[0]["reviewed"] is True
    assert resolve_scenario(set(registered[0]["ability_mapping"]))["registry_id"] == "idpt-windows-collection"
    with pytest.raises(ValueError, match="complete packaged"):
        resolve_scenario({"ability-unknown"})


def test_idpt_registry_rejects_unreviewed_and_duplicate_mappings(monkeypatch):
    monkeypatch.setattr(idpt_registry, "registry", lambda: {"scenarios": [{"reviewed": False, "ability_mapping": {"one": "external"}}]})
    with pytest.raises(ValueError, match="reviewed"):
        idpt_registry.scenarios()
    monkeypatch.setattr(idpt_registry, "registry", lambda: {"scenarios": [{"reviewed": True, "ability_mapping": {"one": "same", "two": "same"}}]})
    with pytest.raises(ValueError, match="one-to-one"):
        idpt_registry.scenarios()


def _cli(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["adversaryflow", *arguments])
    cli.main()
    return json.loads(capsys.readouterr().out)


def test_cli_exposes_normalization_preflight_export_detection_and_coverage(monkeypatch, capsys, tmp_path):
    export = tmp_path / "export.json"
    export.write_text(json.dumps([{"run_id": "run-one", "host_id": "host", "ability_id": "ability", "timestamp": "2026-08-14T12:00:00Z"}]), encoding="utf-8")
    normalized = tmp_path / "normalized.jsonl"
    assert _cli(monkeypatch, capsys, "telemetry", "normalize", "--source", "generic", "--input", str(export), "--output", str(normalized))["record_count"] == 1
    run = tmp_path / "run-one"; run.mkdir()
    event = {"host_id": "host", "ability_id": "ability", "technique_id": "T1057", "behavior_success": True, "cleanup_status": "not-required", "executed_at": "2026-08-14T12:00:00Z", "telemetry": [{"category": "process"}]}
    (run / "events.jsonl").write_text(json.dumps(event) + "\n", encoding="utf-8")
    report = correlate_events([event], "run-one", load_telemetry_records(normalized))
    (run / "telemetry-gap-report.json").write_text(json.dumps(report), encoding="utf-8")
    assert _cli(monkeypatch, capsys, "telemetry", "preflight", "--run-dir", str(run), "--telemetry-file", str(normalized))["ready"] is True
    output = tmp_path / "assessment.csv"
    assert _cli(monkeypatch, capsys, "telemetry", "export", "--run-dir", str(run), "--format", "csv", "--output", str(output))["success"] is True
    assert _cli(monkeypatch, capsys, "detection", "export", "--output", str(tmp_path / "rules"))["mapping_count"] > 0
    assert _cli(monkeypatch, capsys, "coverage", "--campaign-root", str(tmp_path / "empty"))["summary"]["campaigns"] == 0
    abilities = load_catalog("content/abilities/catalog.json")
    categories = sorted({item.category for ability in abilities for item in ability.expected_telemetry})
    snapshot = tmp_path / "sensors.json"
    snapshot.write_text(json.dumps({"host_id": "local-lab", "clock_synchronized": True, "available_sources": categories, "agents": [{"name": "lab-sensor", "health": "healthy"}]}), encoding="utf-8")
    assert _cli(monkeypatch, capsys, "telemetry", "preflight", "--sensor-manifest", str(snapshot))["ready"] is True


def test_cli_creates_gap_derived_retest(monkeypatch, capsys, tmp_path):
    root = tmp_path / "campaigns"
    _, _, source = _completed_campaign(root)
    result = _cli(monkeypatch, capsys, "campaign", "retest", "--campaign-id", source.name, "--campaign-root", str(root))
    assert result["success"] is True
    assert result["retest_of"] == source.name


def test_campaign_sensor_gate_fails_before_execution(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("ADVERSARYFLOW_PROVIDER", "offline")
    snapshot = tmp_path / "unready-sensors.json"
    snapshot.write_text(json.dumps({"host_id": "local-lab", "clock_synchronized": False, "available_sources": [], "agents": [{"name": "lab-sensor", "health": "unhealthy"}]}), encoding="utf-8")
    runs = tmp_path / "runs"
    monkeypatch.setattr(sys, "argv", [
        "adversaryflow", "campaign", "--actor", "baseline", "--objective", "gate execution",
        "--approve", "--approver", "manager@example.test", "--campaign-root", str(tmp_path / "campaigns"),
        "--output", str(runs), "--sensor-manifest", str(snapshot),
    ])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == 1
    assert "Sensor preflight failed" in json.loads(capsys.readouterr().out)["error"]
    assert not runs.exists()
