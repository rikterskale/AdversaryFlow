import json
from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow import lifecycle
from adversaryflow.lifecycle import cancel_campaign, inspect_campaign, list_campaigns, reject_campaign, reset_campaign
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


def test_lifecycle_ignores_campaign_directories_without_metadata():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    (root / "campaign-incomplete").mkdir(parents=True)
    assert list_campaigns(root) == []


def test_reset_requires_confirmation():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    with pytest.raises(PermissionError):
        reset_campaign(root, campaign_id, False)
    reset_campaign(root, campaign_id, True)
    assert not directory.exists()


def test_cancel_records_stop_request():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    cancellation = cancel_campaign(root, campaign_id, "operator requested stop")
    assert json.loads(cancellation.read_text(encoding="utf-8"))["decision"] == "cancelled"
    assert inspect_campaign(root, campaign_id)["metadata"]["status"] == "cancelled"


def test_lifecycle_recovery_rejects_unsafe_roots_invalid_ids_and_missing_campaigns():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    outside_root = Path.cwd().parent / "outside-campaigns"
    with pytest.raises(ValueError, match="inside the current working directory"):
        list_campaigns(outside_root)
    for operation in (
        lambda: inspect_campaign(root, "not-a-campaign"),
        lambda: reject_campaign(root, "not-a-campaign", "manager@example.test", "not scheduled"),
        lambda: cancel_campaign(root, "not-a-campaign", "operator stop"),
        lambda: reset_campaign(root, "not-a-campaign", True),
    ):
        with pytest.raises(ValueError, match="campaign ID"):
            operation()
    missing = "campaign-missing"
    for operation in (
        lambda: inspect_campaign(root, missing),
        lambda: reject_campaign(root, missing, "manager@example.test", "not scheduled"),
        lambda: cancel_campaign(root, missing, "operator stop"),
        lambda: reset_campaign(root, missing, True),
    ):
        with pytest.raises(FileNotFoundError, match=missing):
            operation()
    assert directory.is_dir()
    assert campaign_id == directory.name


def test_lifecycle_rejects_a_campaign_path_that_resolves_outside_its_direct_root(monkeypatch):
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    root.mkdir(parents=True)
    original_resolve = Path.resolve
    candidate = root.resolve() / "campaign-safe"

    def resolved(path, *args, **kwargs):
        if path == candidate:
            return root / "escaped" / "campaign-safe"
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(lifecycle.Path, "resolve", resolved)
    with pytest.raises(ValueError, match="directly under the campaign root"):
        lifecycle._campaign_dir(root, "campaign-safe")


def test_completed_campaign_cannot_be_cancelled_and_is_left_unchanged():
    root = Path("artifacts/test-lifecycle") / str(uuid4())
    directory, campaign_id = _campaign(root)
    metadata_path = directory / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["status"] = "completed"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="cannot be cancelled"):
        cancel_campaign(root, campaign_id, "too late")
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["status"] == "completed"
    assert not (directory / "cancellation.json").exists()
