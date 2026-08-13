"""In-process coverage for safe, non-executing CLI workflow paths."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow import cli
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.provider import ProviderConfig
from adversaryflow.workflow import save_campaign_draft


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


def test_cli_campaign_lifecycle_commands_record_local_decisions(monkeypatch, capsys):
    root = Path("artifacts") / f"cli-lifecycle-{uuid4()}"
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test lifecycle"), load_catalog("content/abilities/catalog.json"))
    first = save_campaign_draft(draft, "hash", "offline", root)
    assert json.loads(_run(monkeypatch, capsys, "campaign", "list", "--campaign-root", str(root)))[0]["campaign_id"] == first.name
    inspected = json.loads(_run(monkeypatch, capsys, "campaign", "inspect", "--campaign-id", first.name, "--campaign-root", str(root)))
    assert inspected["metadata"]["status"] == "awaiting-approval"
    rejected = json.loads(_run(monkeypatch, capsys, "campaign", "reject", "--campaign-id", first.name, "--approver", "manager@example.test", "--reason", "not scheduled", "--campaign-root", str(root)))
    assert rejected["status"] == "rejected"
    second = save_campaign_draft(draft, "hash", "offline", root)
    cancelled = json.loads(_run(monkeypatch, capsys, "campaign", "cancel", "--campaign-id", second.name, "--reason", "operator stop", "--campaign-root", str(root)))
    assert cancelled["status"] == "cancelled"
    reset = json.loads(_run(monkeypatch, capsys, "campaign", "reset", "--campaign-id", second.name, "--confirm", "--campaign-root", str(root)))
    assert reset["status"] == "reset"


def test_cli_campaign_offline_draft_and_synthetic_completion(monkeypatch, capsys):
    monkeypatch.setenv("ADVERSARYFLOW_PROVIDER", "offline")
    root = Path("artifacts") / f"cli-campaign-{uuid4()}"
    drafted = json.loads(_run(monkeypatch, capsys, "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "validate process visibility", "--campaign-root", str(root)))
    assert drafted["stage"] == "drafted"
    completed_root = Path("artifacts") / f"cli-completed-{uuid4()}"
    completed = json.loads(_run(monkeypatch, capsys, "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "validate process visibility", "--approve", "--approver", "manager@example.test", "--campaign-root", str(completed_root), "--output", str(completed_root / "runs")))
    assert completed["stage"] == "completed"
    assert completed["telemetry_gap_report"]["behavior_success"] is True


def test_cli_provider_configure_and_invalid_validation_are_guided(monkeypatch, capsys):
    configured = _run(monkeypatch, capsys, "provider", "configure")
    assert "Offline (default): no configuration required." in configured
    monkeypatch.setattr(cli, "load_provider_config", lambda: ProviderConfig("unsupported", None, None, False))
    monkeypatch.setattr(sys, "argv", ["adversaryflow", "provider", "validate"])
    with pytest.raises(SystemExit) as exit_code:
        cli.main()
    assert exit_code.value.code == 1
    assert "Unsupported provider" in json.loads(capsys.readouterr().out)["errors"][0]


def test_cli_provider_profile_commands_use_nonsecret_profile_helpers(monkeypatch, capsys):
    monkeypatch.setattr(cli, "list_profiles", lambda: {"active": "offline", "profiles": {}})
    assert json.loads(_run(monkeypatch, capsys, "provider", "profile", "list"))["active"] == "offline"
    monkeypatch.setattr(cli, "use_profile", lambda name: Path("artifacts/providers") / f"{name}.json")
    assert json.loads(_run(monkeypatch, capsys, "provider", "profile", "use", "approved"))["active"] == "approved"
    monkeypatch.setattr(cli, "save_profile", lambda *args: Path("artifacts/providers") / f"{args[0]}.json")
    saved = json.loads(_run(monkeypatch, capsys, "provider", "profile", "save", "approved", "--endpoint", "https://example.test/v1", "--model", "approved-model"))
    assert saved["saved"] == "approved"
    removed = []
    monkeypatch.setattr(cli, "remove_profile", lambda name: removed.append(name))
    assert json.loads(_run(monkeypatch, capsys, "provider", "profile", "remove", "approved"))["removed"] == "approved"
    assert removed == ["approved"]


def test_cli_campaign_resume_rejects_tampered_reviewed_inputs(monkeypatch, capsys):
    monkeypatch.setenv("ADVERSARYFLOW_PROVIDER", "offline")
    root = Path("artifacts") / f"cli-tampered-{uuid4()}"
    created = json.loads(_run(monkeypatch, capsys, "campaign", "--roe", "examples/roe.yaml", "--actor", "APT29", "--objective", "validate integrity", "--campaign-root", str(root)))
    metadata_path = root / created["campaign_id"] / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["catalog_sha256"] = "0" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["adversaryflow", "campaign", "--campaign-id", created["campaign_id"], "--campaign-root", str(root)])
    with pytest.raises(SystemExit) as exit_code:
        cli.main()
    assert exit_code.value.code == 1
    assert "catalog_sha256" in json.loads(capsys.readouterr().out)["error"]


def test_cli_campaign_lifecycle_errors_remain_non_destructive(monkeypatch, capsys):
    root = Path("artifacts") / f"cli-errors-{uuid4()}"
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test errors"), load_catalog("content/abilities/catalog.json"))
    campaign = save_campaign_draft(draft, "hash", "offline", root)
    metadata_path = campaign / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["status"] = "completed"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    for command in (
        ("campaign", "cancel", "--campaign-id", campaign.name, "--reason", "too late", "--campaign-root", str(root)),
        ("campaign", "reset", "--campaign-id", campaign.name, "--campaign-root", str(root)),
    ):
        monkeypatch.setattr(sys, "argv", ["adversaryflow", *command])
        with pytest.raises(SystemExit) as exit_code:
            cli.main()
        assert exit_code.value.code == 1
        assert json.loads(capsys.readouterr().out)["success"] is False
    assert campaign.is_dir()


def test_cli_demo_and_support_bundle_stay_local(monkeypatch, capsys):
    root = Path("artifacts") / f"cli-demo-{uuid4()}"
    demo = json.loads(_run(monkeypatch, capsys, "demo", "--roe", "examples/roe.yaml", "--objective", "validate demo", "--output", str(root / "runs")))
    assert demo["telemetry_gap_report"]["behavior_success"] is True
    bundle = Path(_run(monkeypatch, capsys, "support-bundle", "--output", str(root / "support"), "--roe", "examples/roe.yaml").strip())
    assert bundle.is_file()
