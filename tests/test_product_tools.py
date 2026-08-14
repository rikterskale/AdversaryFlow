import json
from pathlib import Path
from uuid import uuid4

from adversaryflow.ai import CampaignRequest, OfflinePlanner
from adversaryflow.emulation import load_catalog
from adversaryflow.product_tools import export_executive_summary, read_roe_editor, save_roe_editor, search_campaign_archive, update_campaign_archive, update_campaign_tags
from adversaryflow.workflow import save_campaign_draft


def _campaign(root: Path) -> str:
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "archive validation"), load_catalog("content/abilities/catalog.json"))
    return save_campaign_draft(draft, "hash", "offline", root).name


def test_archive_tags_and_executive_exports_are_local_and_safe():
    root = Path("artifacts") / f"product-{uuid4()}"
    campaign_id = _campaign(root)
    tagged = update_campaign_tags(str(root), campaign_id, ["release", "visibility"])
    assert tagged["tags"] == ["release", "visibility"]
    controls = update_campaign_archive(str(root), campaign_id, "blue-team", 365)
    assert controls == {"campaign_id": campaign_id, "owner": "blue-team", "retention_days": 365}
    found = search_campaign_archive(str(root), "visibility")
    assert found[0]["campaign_id"] == campaign_id
    assert found[0]["owner"] == "blue-team"
    exported = export_executive_summary(str(root), campaign_id, str(root / "exports"))
    assert Path(exported["markdown"]).read_text(encoding="utf-8").startswith("# AdversaryFlow Executive Summary")
    assert Path(exported["pdf"]).read_bytes().startswith(b"%PDF-1.4")
    assert b"%%EOF" in Path(exported["pdf"]).read_bytes()


def test_roe_editor_validates_saves_and_records_previous_snapshot():
    root = Path("artifacts") / f"roe-editor-{uuid4()}"; root.mkdir(parents=True)
    roe_path = root / "roe.yaml"
    original = {"engagement_name": "Before", "operator_name": "operator", "approver_name": "approver", "approved_targets": ["local-lab"], "dry_run": True}
    roe_path.write_text(__import__("yaml").safe_dump(original), encoding="utf-8")
    loaded = read_roe_editor(str(roe_path), str(root / "history"))
    assert loaded["roe"]["engagement_name"] == "Before"
    saved = save_roe_editor(str(roe_path), {**original, "engagement_name": "After"}, "operator", str(root / "history"))
    assert saved["roe"]["engagement_name"] == "After"
    assert Path(saved["history_entry"]["previous"]).is_file()
    history = json.loads((root / "history" / "history.json").read_text(encoding="utf-8"))
    assert history[-1]["editor"] == "operator"
