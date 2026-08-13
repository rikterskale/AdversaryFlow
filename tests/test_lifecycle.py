import json
from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.lifecycle import inspect_campaign, list_campaigns, reject_campaign, reset_campaign
from adversaryflow.workflow import save_campaign_draft


def _campaign(root: Path) -> tuple[Path, str]:
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    directory = save_campaign_draft(draft, "hash", "offline", root)
    return directory, directory.name


def test_lifecycle_list_inspect_and_reject():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    assert list_campaigns(root)[0]["campaign_id"] == campaign_id
    assert inspect_campaign(root, campaign_id)["draft"]["actor"] == "APT29"
    rejection = reject_campaign(root, campaign_id, "manager@example.test", "Not scheduled")
    assert json.loads(rejection.read_text(encoding="utf-8"))["decision"] == "rejected"


def test_reset_requires_confirmation():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    with pytest.raises(PermissionError):
        reset_campaign(root, campaign_id, False)
    reset_campaign(root, campaign_id, True)
    assert not directory.exists()

