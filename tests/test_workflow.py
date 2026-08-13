from pathlib import Path
from uuid import uuid4

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.models import RulesOfEngagement
from adversaryflow.workflow import approve_draft, build_gap_report, run_local_emulation
from adversaryflow.adapters import AdapterRequest, LocalSyntheticAdapter, preflight_adapter, resolve_adapter


def test_complete_local_workflow():
    abilities = load_catalog("content/abilities/catalog.json")
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "manager", "approved_targets": ["local-lab"]})
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test telemetry"), abilities)
    approval = approve_draft(draft, roe, abilities, "manager", "plan-hash")
    run_dir = run_local_emulation(draft, abilities, approval, Path("artifacts/test-runs") / str(uuid4()))
    progress = __import__("json").loads((run_dir / "progress.json").read_text(encoding="utf-8"))
    assert progress["status"] == "completed"
    assert len(progress["completed_abilities"]) == progress["total_abilities"]
    report = build_gap_report(run_dir)
    assert report["behavior_success"] is True
    assert report["telemetry_expected"] == report["telemetry_observed"]
    assert report["detection_gap_count"] == 0
    manifest = __import__("json").loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["adapter"] == "local-synthetic"
    assert manifest["execution_boundary"] == "simulation-only"
    assert manifest["adapter_preflight"]["contract_version"] == "ADVERSARYFLOW-ADAPTER-1"


def test_rejected_draft_cannot_start_local_emulation():
    abilities = load_catalog("content/abilities/catalog.json")
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "manager", "approved_targets": ["local-lab"]})
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "rejected simulation"), abilities)
    rejection = approve_draft(draft, roe, abilities, "manager", "plan-hash", decision="rejected")
    with __import__("pytest").raises(PermissionError, match="rejected"):
        run_local_emulation(draft, abilities, rejection, Path("artifacts/test-runs") / str(uuid4()))


def test_adapter_rejects_unsupported_name_and_unreviewed_ability():
    abilities = load_catalog("content/abilities/catalog.json")
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test telemetry"), abilities[:1])
    with __import__("pytest").raises(ValueError, match="Unsupported"):
        resolve_adapter("remote-shell")
    with __import__("pytest").raises(ValueError, match="exactly match"):
        LocalSyntheticAdapter().execute(AdapterRequest(draft, abilities, "run-test"))
    adapter, preflight = preflight_adapter("local-synthetic", AdapterRequest(draft, abilities[:1], "run-test"))
    assert adapter.name == preflight.adapter == "local-synthetic"
    assert preflight.network_scopes == ("none",)


def test_adapter_failure_is_recorded_as_a_failed_run(monkeypatch):
    class FailingAdapter:
        name = "local-synthetic"

        def execute(self, request):
            raise RuntimeError("simulated adapter failure")

    import adversaryflow.adapters as adapters

    abilities = load_catalog("content/abilities/catalog.json")
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "manager", "approved_targets": ["local-lab"]})
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test telemetry"), abilities)
    approval = approve_draft(draft, roe, abilities, "manager", "plan-hash")
    monkeypatch.setitem(adapters._REGISTERED_ADAPTERS, "local-synthetic", FailingAdapter())
    output_root = Path("artifacts/test-runs") / str(uuid4())
    with __import__("pytest").raises(RuntimeError, match="simulated"):
        run_local_emulation(draft, abilities, approval, output_root)
    run_dir = next(output_root.iterdir())
    progress = __import__("json").loads((run_dir / "progress.json").read_text(encoding="utf-8"))
    manifest = __import__("json").loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert progress["status"] == manifest["status"] == "failed"
    assert manifest["failure_type"] == "RuntimeError"
