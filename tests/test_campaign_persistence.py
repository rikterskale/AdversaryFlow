from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.models import RulesOfEngagement
from adversaryflow.workflow import campaign_integrity_hashes, load_campaign_draft, save_campaign_draft, verify_campaign_integrity
from pathlib import Path
from uuid import uuid4


def test_campaign_draft_can_be_saved_and_resumed():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    roe = RulesOfEngagement.from_mapping({"engagement_name": "test", "operator_name": "operator@example.test", "approver_name": "manager@example.test", "approved_targets": ["local-lab"]})
    abilities = load_catalog("content/abilities/catalog.json")
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    directory = save_campaign_draft(draft, integrity["plan_hash"], "offline", Path("artifacts/test-campaigns") / str(uuid4()), roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"])
    loaded, metadata = load_campaign_draft(directory)
    assert loaded.as_dict() == draft.as_dict()
    verify_campaign_integrity(loaded, metadata, roe, abilities)


def test_campaign_resume_rejects_tampered_draft():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    roe = RulesOfEngagement.from_mapping({"engagement_name": "test", "operator_name": "operator@example.test", "approver_name": "manager@example.test", "approved_targets": ["local-lab"]})
    abilities = load_catalog("content/abilities/catalog.json")
    integrity = campaign_integrity_hashes(draft, roe, abilities)
    directory = save_campaign_draft(draft, integrity["plan_hash"], "offline", Path("artifacts/test-campaigns") / str(uuid4()), roe_hash=integrity["roe_sha256"], catalog_hash=integrity["catalog_sha256"])
    draft_path = directory / "draft.json"
    data = __import__("json").loads(draft_path.read_text(encoding="utf-8"))
    data["objective"] = "tampered"
    draft_path.write_text(__import__("json").dumps(data), encoding="utf-8")
    loaded, metadata = load_campaign_draft(directory)
    import pytest
    with pytest.raises(ValueError, match="plan_hash"):
        verify_campaign_integrity(loaded, metadata, roe, abilities)
