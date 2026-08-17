import json
import sys
from pathlib import Path
from uuid import uuid4

from adversaryflow import cli
from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.workflow import save_campaign_draft


def _campaign(root: Path) -> str:
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "archive CLI validation"), load_catalog("content/abilities/catalog.json"))
    return save_campaign_draft(draft, "hash", "offline", root).name


def _run(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["adversaryflow", *arguments])
    cli.main()
    return json.loads(capsys.readouterr().out)


def test_archive_cli_exposes_search_metadata_and_export(monkeypatch, capsys):
    root = Path("artifacts") / f"archive-cli-{uuid4()}"
    campaign_id = _campaign(root)
    tagged = _run(monkeypatch, capsys, "archive", "tag", "--campaign-root", str(root), "--campaign-id", campaign_id, "--tags", "Release, visibility")
    assert tagged["tags"] == ["release", "visibility"]
    controls = _run(monkeypatch, capsys, "archive", "controls", "--campaign-root", str(root), "--campaign-id", campaign_id, "--owner", "blue-team", "--retention-days", "365")
    assert controls["owner"] == "blue-team"
    found = _run(monkeypatch, capsys, "archive", "search", "--campaign-root", str(root), "--query", "visibility")
    assert found["campaigns"][0]["campaign_id"] == campaign_id
    exported = _run(monkeypatch, capsys, "archive", "export", "--campaign-root", str(root), "--campaign-id", campaign_id, "--output", str(root / "exports"))
    assert Path(exported["markdown"]).is_file()
    assert Path(exported["pdf"]).read_bytes().startswith(b"%PDF-1.4")
