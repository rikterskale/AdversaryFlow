import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from adversaryflow.product_features import adapter_compatibility, author_catalog, branch_campaign, cleanup_retention, coverage_trends, import_detection_rules, list_campaign_templates, retention_preview, save_campaign_template, schedule_retest, score_detection_rules


def test_templates_and_schedules_are_local_review_plans(tmp_path):
    templates = tmp_path / "templates"
    saved = save_campaign_template("endpoint-check", "APT29", "validate telemetry", root=templates)
    assert saved["boundary"].startswith("Template only")
    assert list_campaign_templates(templates)[0]["name"] == "endpoint-check"
    schedule = schedule_retest("weekly", "endpoint-check", 7, tmp_path / "schedules")
    assert schedule["status"] == "planned"
    assert "automatic" in schedule["boundary"]


def test_detection_import_is_offline_and_retention_preview_is_safe(tmp_path):
    source = tmp_path / "rules.json"
    source.write_text(json.dumps({"rules": [{"id": "rule-1", "technique": "T1059"}]}), encoding="utf-8")
    imported = import_detection_rules(str(source), str(tmp_path / "detection"))
    assert imported["rule_count"] == 1
    assert "deployed" in imported["boundary"]
    preview = retention_preview(tmp_path / "campaigns")
    assert preview["count"] == 0
    assert "Preview only" in preview["boundary"]


def test_detection_scoring_and_retention_confirmation(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{"rule_id": "rule-1", "technique_id": "T1059"}]}), encoding="utf-8")
    scored = score_detection_rules(tmp_path / "campaigns", rules)
    assert scored["summary"] == {"rules": 1, "matched": 0, "unmatched": 1}
    with pytest.raises(PermissionError):
        cleanup_retention(tmp_path / "campaigns")


def test_feature_validation_rejects_unsafe_names_and_cadence(tmp_path):
    with pytest.raises(ValueError):
        save_campaign_template("Bad Name", "APT29", "validate", root=tmp_path / "templates")
    with pytest.raises(ValueError):
        schedule_retest("weekly", "template", 0, root=tmp_path / "schedules")
    with pytest.raises(ValueError):
        save_campaign_template("empty", "", "validate", root=tmp_path / "templates")
    with pytest.raises(ValueError):
        save_campaign_template("outside", "APT29", "validate", root=Path.cwd().parent / "outside")


def test_feature_empty_and_invalid_inputs_fail_closed(tmp_path):
    assert list_campaign_templates(tmp_path / "missing") == []
    bad = tmp_path / "bad.json"; bad.write_text(json.dumps({"rules": "not-a-list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        import_detection_rules(str(bad), str(tmp_path / "out"))
    jsonl = tmp_path / "rules.jsonl"; jsonl.write_text('{"id":"rule-1"}\n{"id":"rule-2"}\n', encoding="utf-8")
    assert import_detection_rules(str(jsonl), str(tmp_path / "jsonl-out"))["rule_count"] == 2
    assert cleanup_retention(tmp_path / "campaigns", confirm=True)["count"] == 0


def test_scoring_and_retention_process_local_campaign_records(tmp_path):
    campaigns = tmp_path / "campaigns"; campaign = campaigns / "campaign-one"; run = tmp_path / "run-one"
    campaign.mkdir(parents=True); run.mkdir()
    (campaign / "metadata.json").write_text(json.dumps({"campaign_id": "campaign-one", "run_dir": str(run), "retention_days": 1, "created_at": "2020-01-01T00:00:00+00:00"}), encoding="utf-8")
    (run / "telemetry-gap-report.json").write_text(json.dumps({"results": [{"technique_id": "T1059", "ability_id": "ability-one", "telemetry_status": "detected"}]}), encoding="utf-8")
    rules = tmp_path / "rules.json"; rules.write_text(json.dumps({"rules": [{"technique_id": "T1059", "ability_id": "ability-one"}]}), encoding="utf-8")
    assert score_detection_rules(campaigns, rules)["summary"]["matched"] == 1
    preview = retention_preview(campaigns, datetime(2021, 1, 1, tzinfo=timezone.utc))
    assert preview["count"] == 1
    assert cleanup_retention(campaigns, confirm=True)["removed"] == ["campaign-one"]


def test_branch_trends_catalog_authoring_and_adapter_discovery(tmp_path):
    campaigns = tmp_path / "campaigns"; source = campaigns / "campaign-source"; source.mkdir(parents=True)
    (source / "metadata.json").write_text(json.dumps({"campaign_id": "campaign-source", "status": "completed", "created_at": "2024-01-01T00:00:00+00:00"}), encoding="utf-8")
    (source / "approval.json").write_text("{}", encoding="utf-8")
    branch = branch_campaign(campaigns, "campaign-source", "alternative")
    assert branch["branch_of"] == "campaign-source"
    assert not (campaigns / "campaign-alternative" / "approval.json").exists()
    with pytest.raises(FileExistsError):
        branch_campaign(campaigns, "campaign-source", "alternative")
    with pytest.raises(FileNotFoundError):
        branch_campaign(campaigns, "campaign-missing", "other")
    assert coverage_trends(campaigns)["points"][0]["campaigns"] == 2
    catalog = Path("content/abilities/catalog.json")
    authored = author_catalog(str(catalog), str(tmp_path / "catalog.json"), "local-draft", "1.2.3")
    assert authored["version"] == "1.2.3"
    compatibility = adapter_compatibility(str(catalog))
    assert len(compatibility["adapters"]) == 3


def test_trend_and_retention_skip_unusable_records(tmp_path):
    campaigns = tmp_path / "campaigns"; campaign = campaigns / "campaign-skip"; campaign.mkdir(parents=True)
    (campaign / "metadata.json").write_text(json.dumps({"campaign_id": "campaign-skip", "created_at": "2024-01-02T00:00:00+00:00", "retention_days": "never"}), encoding="utf-8")
    assert retention_preview(campaigns)["count"] == 0
    assert coverage_trends(campaigns)["points"][0]["campaigns"] == 1
