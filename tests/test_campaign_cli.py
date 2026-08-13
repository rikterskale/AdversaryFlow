import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4


def test_campaign_drafts_without_approval():
    env = {**os.environ, "PYTHONPATH": "src", "ADVERSARYFLOW_PROVIDER": "offline"}
    result = subprocess.run([sys.executable, "-m", "adversaryflow", "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "test campaign"], capture_output=True, text=True, env=env, check=True)
    payload = json.loads(result.stdout)
    assert payload["stage"] == "drafted"
    assert payload["approval_required"] is True
    assert "run_dir" not in payload


def test_campaign_requires_named_roe_approver():
    env = {**os.environ, "PYTHONPATH": "src", "ADVERSARYFLOW_PROVIDER": "offline"}
    result = subprocess.run([sys.executable, "-m", "adversaryflow", "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "test campaign", "--approve", "--approver", "wrong@example.test"], capture_output=True, text=True, env=env)
    assert result.returncode != 0
    assert "Only the approver named in the RoE" in result.stdout


def test_campaign_can_fallback_to_offline_provider():
    env = {**os.environ, "PYTHONPATH": "src", "ADVERSARYFLOW_PROVIDER": "unsupported-provider"}
    result = subprocess.run([sys.executable, "-m", "adversaryflow", "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "provider recovery", "--fallback-offline", "--campaign-root", "artifacts/test-fallback-campaigns"], capture_output=True, text=True, env=env, check=True)
    assert json.loads(result.stdout)["provider"] == "offline-fallback"


def test_campaign_cli_rejects_resumption_when_reviewed_integrity_changes():
    env = {**os.environ, "PYTHONPATH": "src", "ADVERSARYFLOW_PROVIDER": "offline"}
    root = Path("artifacts/test-cli-integrity") / str(uuid4())
    created = subprocess.run([sys.executable, "-m", "adversaryflow", "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "test integrity", "--campaign-root", str(root)], capture_output=True, text=True, env=env, check=True)
    campaign_id = json.loads(created.stdout)["campaign_id"]
    metadata_path = root / campaign_id / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["roe_sha256"] = "0" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    resumed = subprocess.run([sys.executable, "-m", "adversaryflow", "campaign", "--campaign-id", campaign_id, "--campaign-root", str(root)], capture_output=True, text=True, env=env)
    assert resumed.returncode != 0
    assert "roe_sha256" in resumed.stdout
