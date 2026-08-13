import json
from pathlib import Path
from uuid import uuid4

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.reports import write_campaign_reports
from adversaryflow.workflow import save_campaign_draft


def test_campaign_reports_are_written():
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    directory = save_campaign_draft(draft, "hash", "offline", Path("artifacts/test-reports") / str(uuid4()))
    markdown, html_report = write_campaign_reports(directory)
    assert markdown.exists() and html_report.exists()
    assert "hash" in markdown.read_text(encoding="utf-8")
