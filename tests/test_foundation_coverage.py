"""Coverage for offline foundational safety and planning helpers."""

import json

import pytest

from adversaryflow import intel, platforms
from adversaryflow.models import RulesOfEngagement
from adversaryflow.planner import build_plan
from adversaryflow.safety import require_simulation_action


def _roe(*, actions=("simulation", "telemetry_validation")):
    return RulesOfEngagement.from_mapping({
        "engagement_name": "test",
        "operator_name": "operator",
        "approver_name": "approver",
        "approved_targets": ["local-lab"],
        "excluded_targets": ["production"],
        "allowed_actions": list(actions),
    })


@pytest.mark.parametrize(("identifier", "expected"), [("kali", "Kali"), ("ubuntu", "Ubuntu"), ("raspbian", "Debian"), ("fedora", "Linux")])
def test_platform_detection_reads_supported_linux_release_data(monkeypatch, identifier, expected):
    class Release:
        def exists(self): return True
        def read_text(self, **_kwargs): return f'ID="{identifier}"\nNAME=test\n'

    monkeypatch.setattr(platforms.platform, "system", lambda: "Linux")
    monkeypatch.setattr(platforms, "Path", lambda _path: Release())
    assert platforms.detect_platform() == expected


def test_platform_detection_and_supported_check_handle_windows(monkeypatch):
    monkeypatch.setattr(platforms.platform, "system", lambda: "Windows")
    assert platforms.detect_platform() == "Windows"
    assert platforms.platform_supported() is True


def test_safety_action_and_plan_building_preserve_simulation_only_scope():
    roe = _roe()
    require_simulation_action(roe, "simulation")
    technique = {"name": "Command and Scripting Interpreter", "external_references": [{"external_id": "T1059"}]}
    plan = build_plan(roe, "APT29", "local-lab", technique, "offline fixture")
    assert plan.steps[0].technique_id == "T1059"
    assert "without changing system state" in plan.steps[0].objective
    with pytest.raises(PermissionError):
        require_simulation_action(_roe(actions=("telemetry_validation",)), "simulation")


def test_intel_lookup_is_offline_and_https_constrained(monkeypatch):
    with pytest.raises(ValueError, match="HTTPS"):
        intel.fetch_attack_bundle("http://example.test/attack.json")

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return json.dumps({"objects": [{"name": "Technique", "external_references": [{"external_id": "T1003"}]}]}).encode()

    monkeypatch.setattr(intel, "urlopen", lambda request, timeout: Response())
    bundle = intel.fetch_attack_bundle("https://example.test/attack.json")
    assert intel.find_technique(bundle, "T1003")["name"] == "Technique"
    assert intel.find_technique(bundle, "T9999") is None
