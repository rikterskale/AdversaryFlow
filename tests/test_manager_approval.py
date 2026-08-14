import json
from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow.manager import _approve_and_run, _offline_draft


def _draft(root: str) -> str:
    result = _offline_draft(root, "examples/roe.yaml", "content/abilities/catalog.json", {
        "actor": "APT29", "target": "local-lab", "objective": "verify manager approval",
    })
    return result["campaign_id"]


def test_manager_approval_runs_only_after_campaign_specific_confirmation():
    root = f"artifacts/test-manager-approval-{uuid4()}"
    campaign_id = _draft(root)
    with pytest.raises(PermissionError, match="Type 'APPROVE"):
        _approve_and_run(root, "examples/roe.yaml", "content/abilities/catalog.json", campaign_id, {
            "approver": "manager@example.test", "confirmation": "APPROVE something-else",
        })

    result = _approve_and_run(root, "examples/roe.yaml", "content/abilities/catalog.json", campaign_id, {
        "approver": "manager@example.test", "confirmation": f"APPROVE {campaign_id}",
    })
    metadata = json.loads((Path(root) / campaign_id / "metadata.json").read_text(encoding="utf-8"))
    assert result["stage"] == "completed"
    assert metadata["status"] == "completed"
    assert (Path(root) / campaign_id / "approval.json").is_file()
    assert (Path(root) / campaign_id / "campaign-report.html").is_file()
