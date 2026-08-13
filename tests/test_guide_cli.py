import os
import subprocess
import sys


def test_campaign_guide_explains_safe_campaign_lifecycle():
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run([sys.executable, "-m", "adversaryflow", "guide", "--actor", "APT29", "--target", "local-lab", "--objective", "validate telemetry"], capture_output=True, text=True, env=env, check=True)
    assert "1. Prepare the local environment" in result.stdout
    assert "simulation-only" in result.stdout
    assert 'adversaryflow campaign --actor "APT29" --target "local-lab" --objective "validate telemetry"' in result.stdout
    assert "adversaryflow manager --open" in result.stdout
