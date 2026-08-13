import json
import os
import subprocess
import sys


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
