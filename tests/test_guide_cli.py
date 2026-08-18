import os
import subprocess
import sys

from adversaryflow.cli import completion_script, quickstart_human, quickstart_payload


def test_campaign_guide_explains_safe_campaign_lifecycle():
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run([sys.executable, "-m", "adversaryflow", "guide", "--actor", "APT29", "--target", "local-lab", "--objective", "validate telemetry"], capture_output=True, text=True, env=env, check=True)
    assert "1. Prepare the local environment" in result.stdout
    assert "simulation-only" in result.stdout
    assert 'adversaryflow campaign --actor "APT29" --target "local-lab" --objective "validate telemetry"' in result.stdout
    assert "it does not contact the target, run a command, use a hosted provider, approve the campaign, or start emulation." in result.stdout
    assert "adversaryflow manager --open" in result.stdout


def test_completion_scripts_cover_supported_shells():
    assert "complete -F" in completion_script("bash")
    assert "#compdef" in completion_script("zsh")
    assert "complete -c" in completion_script("fish")
    assert "Register-ArgumentCompleter" in completion_script("powershell")


def test_quickstart_is_offline_and_points_to_safe_next_steps():
    payload = quickstart_payload()
    assert payload["ready"] is True
    assert payload["offline_default"] is True
    assert payload["api_key_required"] is False
    assert "adversaryflow demo" in payload["next_steps"]
    text = quickstart_human(payload)
    assert "AdversaryFlow starts offline" in text
    assert "doctor --fix --json" in text
