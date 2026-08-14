"""Shared persisted-campaign completion service for CLI and local manager."""

import json
from pathlib import Path

from .emulation import Ability
from .lifecycle import inspect_campaign
from .models import RulesOfEngagement
from .reports import write_campaign_reports
from .workflow import approve_draft, build_gap_report, load_campaign_draft, run_local_emulation, verify_campaign_integrity


def complete_saved_campaign(campaign_root: str, campaign_id: str, roe: RulesOfEngagement, abilities: tuple[Ability, ...], approver: str, output_root: str) -> dict[str, object]:
    """Revalidate, approve, emulate, and report on one immutable reviewed draft."""
    campaign = inspect_campaign(campaign_root, campaign_id)
    if campaign.get("metadata", {}).get("status") != "awaiting-approval":
        raise ValueError("Only campaigns awaiting approval can be approved and run")
    draft, metadata = load_campaign_draft(campaign["campaign_dir"])
    verify_campaign_integrity(draft, metadata, roe, abilities)
    approval = approve_draft(draft, roe, abilities, approver, metadata["plan_hash"])
    run_dir = run_local_emulation(draft, abilities, approval, output_root)
    campaign_dir = Path(campaign["campaign_dir"])
    (campaign_dir / "approval.json").write_text(json.dumps(approval.__dict__, indent=2), encoding="utf-8")
    metadata.update({"status": "completed", "run_dir": str(run_dir)})
    (campaign_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    write_campaign_reports(campaign_dir, run_dir)
    return {"stage": "completed", "campaign_id": campaign_id, "approval": approval.__dict__, "run_dir": str(run_dir), "telemetry_gap_report": build_gap_report(run_dir)}
