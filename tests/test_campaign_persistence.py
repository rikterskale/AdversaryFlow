from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.workflow import load_campaign_draft, save_campaign_draft
from pathlib import Path
from uuid import uuid4


def test_campaign_draft_can_be_saved_and_resumed():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    directory = save_campaign_draft(draft, "hash-123", "offline", Path("artifacts/test-campaigns") / str(uuid4()))
    loaded, metadata = load_campaign_draft(directory)
    assert loaded.as_dict() == draft.as_dict()
    assert metadata["plan_hash"] == "hash-123"
