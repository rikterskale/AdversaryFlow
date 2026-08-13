import json
from pathlib import Path
from uuid import uuid4

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.reports import build_campaign_report, write_campaign_reports
from adversaryflow.workflow import save_campaign_draft


def test_campaign_reports_are_written():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    directory = save_campaign_draft(draft, "hash", "offline", Path("artifacts/test-reports") / str(uuid4()))
    markdown, html_report = write_campaign_reports(directory)
    assert markdown.exists() and html_report.exists()
    assert "hash" in markdown.read_text(encoding="utf-8")


def test_campaign_report_reads_a_selected_local_telemetry_summary():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "report"), load_catalog("content/abilities/catalog.json"))
    directory = save_campaign_draft(draft, "hash", "offline", Path("artifacts/test-reports") / str(uuid4()))
    run = directory / "run"
    run.mkdir()
    (run / "telemetry-gap-report.json").write_text('{"behavior_success": true, "gaps": []}', encoding="utf-8")
    assert build_campaign_report(directory, run)["run"]["behavior_success"] is True
