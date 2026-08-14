"""Deterministic validation and recovery coverage without external side effects."""

import json
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

from adversaryflow.ai import AICampaignDraft, CampaignRequest, OfflinePlanner, build_ai_request_prompt, build_review_prompt, validate_ai_draft
from adversaryflow.doctor import run_doctor
from adversaryflow.emulation import load_catalog
from adversaryflow.models import CampaignPlan, CampaignStep, RulesOfEngagement
from adversaryflow.profiles import remove_profile, use_profile
from adversaryflow.reports import build_campaign_report, write_campaign_reports
from adversaryflow.workflow import approve_draft, build_gap_report, campaign_integrity_hashes, save_campaign_draft, verify_campaign_integrity


def _roe():
    return RulesOfEngagement.from_mapping({"engagement_name": "test", "operator_name": "operator", "approver_name": "approver", "approved_targets": ["local-lab"]})


def test_ai_review_and_validation_fail_closed_on_bad_drafts():
    abilities = load_catalog("content/abilities/catalog.json")
    plan = CampaignPlan("APT29", "local-lab", "fixture", (CampaignStep("T1003", "Fixture", "objective", "synthetic", (), ()),))
    assert "Do not add executable offensive commands" in build_review_prompt(plan)
    assert "Always set approval_required to true" in build_ai_request_prompt(CampaignRequest("APT29", "local-lab", "test"), abilities)
    baseline = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), abilities)
    for replacement, message in [
        ({"target": "production"}, "outside the approved"),
        ({"ability_ids": ("unknown",)}, "unknown abilities"),
        ({"approval_required": False}, "must require human"),
        ({"risk_level": "Critical"}, "risk_level is invalid"),
    ]:
        data = baseline.as_dict() | replacement
        candidate = AICampaignDraft(**{key: tuple(value) if key in {"ability_ids", "expected_telemetry", "stop_conditions", "assumptions", "source_refs"} else value for key, value in data.items()})
        with pytest.raises(ValueError, match=message):
            validate_ai_draft(candidate, _roe(), abilities)


def test_doctor_reports_dependency_catalog_and_loopback_failures(monkeypatch):
    import adversaryflow.doctor as doctor

    real_import = doctor.importlib.import_module
    monkeypatch.setattr(doctor.importlib, "import_module", lambda name: (_ for _ in ()).throw(ImportError()) if name == "yaml" else real_import(name))
    monkeypatch.setattr(doctor, "load_catalog", lambda _path: (_ for _ in ()).throw(ValueError("catalog fixture failure")))

    class BrokenSocket:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def bind(self, _address): raise OSError("loopback fixture failure")

    monkeypatch.setattr(doctor.socket, "socket", BrokenSocket)
    result = run_doctor("artifacts/missing-roe.yaml", "artifacts/missing-catalog.json")
    failures = {item["name"]: item for item in result["checks"] if not item["passed"]}
    assert {"dependency:PyYAML", "roe", "ability-catalog", "loopback"}.issubset(failures)
    assert result["guided_fixes"]


def test_reports_profiles_and_workflow_recovery_edges_are_local():
    root = Path("artifacts") / f"validation-{uuid4()}"
    abilities = load_catalog("content/abilities/catalog.json")
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), abilities)
    campaign = save_campaign_draft(draft, "hash", "offline", root)
    report = build_campaign_report(campaign)
    assert report["approval"] is None and report["run"] is None
    markdown, html = write_campaign_reports(campaign)
    assert markdown.is_file() and html.is_file()
    assert "None recorded" in markdown.read_text(encoding="utf-8")
    with pytest.raises(KeyError): use_profile("missing", root / "profiles")
    with pytest.raises(ValueError): remove_profile("offline", root / "profiles")
    hashes = campaign_integrity_hashes(draft, _roe(), abilities)
    with pytest.raises(ValueError, match="missing plan_hash"):
        verify_campaign_integrity(draft, {}, _roe(), abilities)
    with pytest.raises(PermissionError): approve_draft(draft, _roe(), abilities, "wrong", hashes["plan_hash"])
    with pytest.raises(ValueError, match="decision"):
        approve_draft(draft, _roe(), abilities, "approver", hashes["plan_hash"], decision="invalid")
    empty = root / "empty-run"
    empty.mkdir(parents=True)
    (empty / "events.jsonl").write_text("", encoding="utf-8")
    assert build_gap_report(empty)["behavior_success"] is False
