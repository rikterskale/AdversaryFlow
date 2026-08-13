"""In-process coverage for safe, non-executing CLI workflow paths."""

import json
import sys

import pytest

from adversaryflow import cli


def _run(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["adversaryflow", *arguments])
    cli.main()
    return capsys.readouterr().out


def test_cli_guide_and_validate_paths_are_safe_and_descriptive(monkeypatch, capsys):
    guide = _run(monkeypatch, capsys, "guide", "--actor", "APT29", "--target", "local-lab", "--objective", "validate visibility")
    assert "simulation-only" in guide
    assert 'campaign --actor "APT29"' in guide
    validation = json.loads(_run(monkeypatch, capsys, "validate", "examples/roe.yaml"))
    assert validation == {"valid": True, "engagement": "Local Purple-Team Telemetry Validation", "dry_run": True}


def test_cli_manager_passes_only_explicit_local_configuration(monkeypatch, capsys):
    received = {}
    monkeypatch.setattr(cli, "serve_manager", lambda *args: received.update(args=args))
    _run(monkeypatch, capsys, "manager", "--host", "127.0.0.1", "--port", "8899", "--campaign-root", "artifacts/cli-manager", "--roe", "examples/roe.yaml", "--catalog", "content/abilities/catalog.json")
    assert received["args"] == ("127.0.0.1", 8899, "artifacts/cli-manager", False, "examples/roe.yaml", "content/abilities/catalog.json")


def test_cli_provider_diagnose_and_campaign_list_are_nonexecuting(monkeypatch, capsys):
    diagnose = json.loads(_run(monkeypatch, capsys, "provider", "diagnose"))
    assert any("Offline mode requires no key" in item for item in diagnose["recovery"])
    listed = json.loads(_run(monkeypatch, capsys, "campaign", "list", "--campaign-root", "artifacts/cli-empty-campaigns"))
    assert listed == []


def test_cli_doctor_json_exits_successfully_after_safe_checks(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["adversaryflow", "doctor", "--json"])
    with pytest.raises(SystemExit) as exit_code:
        cli.main()
    assert exit_code.value.code == 0
    assert json.loads(capsys.readouterr().out)["passed"] is True


def test_cli_capabilities_and_provider_status_are_read_only(monkeypatch, capsys):
    capabilities = _run(monkeypatch, capsys, "capabilities")
    advertised = json.loads(capabilities)
    assert advertised["format"] == "ADVERSARYFLOW-CAPABILITIES-1"
    assert advertised["capabilities"]
    status = json.loads(_run(monkeypatch, capsys, "provider", "status"))
    assert status["provider"] == "offline"


def test_cli_provider_validate_exits_successfully_for_offline_defaults(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["adversaryflow", "provider", "validate"])
    with pytest.raises(SystemExit) as exit_code:
        cli.main()
    assert exit_code.value.code == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_cli_draft_path_generates_an_offline_reviewable_plan(monkeypatch, capsys):
    drafted = json.loads(_run(monkeypatch, capsys, "draft", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "validate process visibility"))
    assert drafted["mode"] == "offline-ai-fallback"
    assert drafted["draft"]["target"] == "local-lab"
