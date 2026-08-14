import json
from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow import cli, intel
from adversaryflow.enrichment import build_enriched_coverage, write_enriched_coverage
from adversaryflow.emulation import Ability, TelemetryExpectation, load_catalog, validate_ability
from adversaryflow.intel import fetch_ctid_technique_ids, find_group, group_technique_ids


def _bundle():
    return {"objects": [
        {"type": "intrusion-set", "id": "intrusion-set--axiom", "name": "Axiom", "aliases": ["Group 72"]},
        {"type": "attack-pattern", "id": "attack-pattern--one", "name": "Accessibility Features", "external_references": [{"external_id": "T1546.008"}]},
        {"type": "attack-pattern", "id": "attack-pattern--two", "name": "Data from Local System", "external_references": [{"external_id": "T1005"}]},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--axiom", "target_ref": "attack-pattern--one"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--axiom", "target_ref": "attack-pattern--two"},
    ]}


def test_group_lookup_and_relationships_are_exact_and_current():
    assert find_group(_bundle(), "group 72")["name"] == "Axiom"
    assert group_technique_ids(_bundle(), "Axiom") == ("T1005", "T1546.008")
    with pytest.raises(ValueError, match="Actor not found"):
        group_technique_ids(_bundle(), "Missing")


def test_enrichment_fills_exact_ability_and_procedure_gaps():
    coverage = build_enriched_coverage("Axiom", "windows", _bundle(), ("T1546.008",), "content/abilities/catalog.json", {
        "format": "ADVERSARYFLOW-BENIGN-PROCEDURES-1", "procedures": [{"id": "procedure-dummy-data-read", "technique_id": "T1005", "name": "existing", "action": "safe", "source": "dlp", "expected_detection": "event", "cleanup": "remove"}],
    })
    assert coverage["discovered_technique_ids"] == ["T1005", "T1546.008"]
    assert len(coverage["generated_ability_ids"]) == 2
    assert coverage["generated_procedure_ids"] == ["procedure-intel-t1546-008-windows"]
    generated = next(item for item in coverage["catalog"]["abilities"] if item["technique"]["id"] == "T1546.008")
    assert generated["safety"] == {"writes_only_run_root": True, "network_scope": "none"}
    assert "do not perform" in generated["simulation_action"]
    assert generated["source_refs"] == ["MITRE ATT&CK Enterprise STIX", "CTID Adversary Emulation Library"]
    existing_procedure_ability = next(item for item in coverage["catalog"]["abilities"] if item["technique"]["id"] == "T1005")
    assert existing_procedure_ability["procedure_id"] == "procedure-dummy-data-read"
    procedure_ids = {item["id"] for item in coverage["procedures"]["procedures"]}
    assert all(item.get("procedure_id") in procedure_ids for item in coverage["catalog"]["abilities"] if item["technique"]["id"] in coverage["discovered_technique_ids"])


def test_enrichment_reports_ctid_ids_missing_from_attack_metadata():
    coverage = build_enriched_coverage("Axiom", "windows", _bundle(), ("T9999",), "content/abilities/catalog.json", {"procedures": []})
    assert coverage["unresolved_technique_ids"] == ["T9999"]


class _Response:
    def __init__(self, value, raw=False): self.value = value; self.raw = raw
    def __enter__(self): return self
    def __exit__(self, *_args): return False
    def read(self, *_args): return self.value if self.raw else json.dumps(self.value).encode()


def test_ctid_lookup_reads_only_matching_metadata_files(monkeypatch):
    tree = {"tree": [
        {"type": "blob", "path": "apt29/Emulation_Plan/plan.yaml", "size": 100},
        {"type": "blob", "path": "apt29/payload.exe", "size": 100},
        {"type": "blob", "path": "fin7/plan.yaml", "size": 100},
        {"type": "tree", "path": "apt29", "size": 0},
        {"type": "blob", "path": "apt29/huge.json", "size": 2_000_001},
    ]}
    monkeypatch.setattr(intel, "urlopen", lambda request, timeout: _Response(b"steps: [T1059.001, T1005]", raw=True) if "raw.githubusercontent.com" in request.full_url else _Response(tree))
    assert fetch_ctid_technique_ids("APT29") == ("T1005", "T1059.001")
    with pytest.raises(ValueError, match="official HTTPS GitHub API"):
        fetch_ctid_technique_ids("APT29", "https://example.test/tree")
    monkeypatch.setattr(intel, "urlopen", lambda *_args, **_kwargs: _Response({"truncated": True}))
    with pytest.raises(ValueError, match="truncated"):
        fetch_ctid_technique_ids("APT29")


def test_ctid_lookup_rejects_oversized_download(monkeypatch):
    tree = {"tree": [{"type": "blob", "path": "apt29/plan.md", "size": 10}]}
    monkeypatch.setattr(intel, "urlopen", lambda request, timeout: _Response(b"x" * 2_000_001, raw=True) if "raw.githubusercontent.com" in request.full_url else _Response(tree))
    with pytest.raises(ValueError, match="safe import limit"):
        fetch_ctid_technique_ids("APT29")


def test_enrichment_writes_a_runnable_synthetic_plan_inside_workspace():
    root = Path("artifacts") / f"enrichment-{uuid4()}"
    coverage = build_enriched_coverage("Axiom", "windows", _bundle(), (), "content/abilities/catalog.json", {"procedures": []})
    result = write_enriched_coverage(coverage, root)
    assert Path(result["catalog"]).is_file()
    assert {item.technique_id for item in load_catalog(result["catalog"]) if item.platform == "windows"} == {"T1005", "T1546.008"}
    plan = json.loads(Path(result["emulation_plan"]).read_text(encoding="utf-8"))
    assert [item["technique_id"] for item in plan["steps"]] == ["T1005", "T1546.008"]
    assert plan["execution_boundary"] == "simulation-only"
    with pytest.raises(ValueError, match="inside the current working directory"):
        write_enriched_coverage(coverage, Path.cwd().parent / "outside")


def test_enriched_ability_procedure_references_are_validated():
    ability = Ability("id", "1", "name", "T1005", "windows", "synthetic", "marker", (TelemetryExpectation("synthetic", "event"),), procedure_id="invalid")
    with pytest.raises(ValueError, match="procedure_id"):
        validate_ability(ability)


def test_cli_intel_sync_writes_reviewable_outputs(monkeypatch, capsys):
    root = Path("artifacts") / f"cli-enrichment-{uuid4()}"
    monkeypatch.setattr(cli, "fetch_attack_bundle", _bundle)
    monkeypatch.setattr(cli, "fetch_ctid_technique_ids", lambda actor: ("T1546.008",))
    monkeypatch.setattr("sys.argv", ["adversaryflow", "intel-sync", "--actor", "Axiom", "--platform", "windows", "--output", str(root)])
    cli.main()
    result = json.loads(capsys.readouterr().out)
    assert result["success"] is True
    assert result["generated_ability_ids"]
    assert "campaign --actor" in result["next"]

    monkeypatch.setattr(cli, "fetch_attack_bundle", lambda: (_ for _ in ()).throw(ValueError("source failed")))
    monkeypatch.setattr("sys.argv", ["adversaryflow", "intel-sync", "--actor", "Axiom", "--mitre-only"])
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == 1
    assert "No commands or payloads" in capsys.readouterr().out
