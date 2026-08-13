from pathlib import Path
from uuid import uuid4

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.models import RulesOfEngagement
from adversaryflow.workflow import approve_draft, build_gap_report, run_local_emulation


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
