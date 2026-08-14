"""Create immutable review drafts from recorded detection gaps."""

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from .ai import AICampaignDraft, validate_ai_draft
from .emulation import Ability
from .lifecycle import inspect_campaign
from .models import RulesOfEngagement
from .workflow import campaign_integrity_hashes, load_campaign_draft, save_campaign_draft


def create_gap_retest(campaign_root: str | Path, campaign_id: str, roe: RulesOfEngagement, abilities: tuple[Ability, ...]) -> dict[str, Any]:
    source = inspect_campaign(campaign_root, campaign_id)
    draft, metadata = load_campaign_draft(source["campaign_dir"])
    if metadata.get("status") != "completed" or not metadata.get("run_dir"):
        raise ValueError("A retest requires a completed source campaign")
    report_path = Path(str(metadata["run_dir"])) / "telemetry-gap-report.json"
    if not report_path.is_file():
        raise ValueError("The source campaign has no telemetry gap report")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    gap_ids = {str(item.get("ability_id")) for item in report.get("gaps", []) if item.get("ability_id")}
    selected = tuple(ability for ability in abilities if ability.id in gap_ids and ability.id in draft.ability_ids)
    if not selected:
        raise ValueError("The source campaign has no unresolved cataloged detection gaps")
    retest = replace(
        draft,
        objective=f"Retest {len(selected)} detection gap(s) from {campaign_id}: {draft.objective}",
        ability_ids=tuple(ability.id for ability in selected),
        expected_telemetry=tuple(item.description for ability in selected for item in ability.expected_telemetry),
        assumptions=(*draft.assumptions, f"Derived from immutable source campaign {campaign_id} and run {Path(str(metadata['run_dir'])).name}."),
    )
    validate_ai_draft(retest, roe, abilities)
    integrity = campaign_integrity_hashes(retest, roe, abilities)
    directory = save_campaign_draft(
        retest, integrity["plan_hash"], "offline-retest", campaign_root,
        provider_metadata={"provider": "offline-retest", "status": "gap-derived", "source_campaign_id": campaign_id},
        roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"],
    )
    metadata_path = directory / "metadata.json"
    retest_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    retest_metadata.update({"retest_of": campaign_id, "source_run_id": report.get("run_id"), "source_gap_count": len(selected)})
    metadata_path.write_text(json.dumps(retest_metadata, indent=2), encoding="utf-8")
    provenance = {"schema": "ADVERSARYFLOW-RETEST-1", "retest_campaign_id": directory.name, "source_campaign_id": campaign_id, "source_run_id": report.get("run_id"), "ability_ids": list(retest.ability_ids), "source_gap_statuses": [item for item in report.get("gaps", []) if item.get("ability_id") in gap_ids]}
    (directory / "retest.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    return {"campaign_id": directory.name, "retest_of": campaign_id, "ability_ids": list(retest.ability_ids), "gap_count": len(selected), "stage": "drafted", "approval_required": True}
