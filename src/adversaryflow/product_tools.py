"""Local-only product workflows for the Manager UI."""

import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .lifecycle import inspect_campaign, list_campaigns
from .models import RulesOfEngagement
from .reports import build_campaign_report


def _workspace_path(path: str | Path) -> Path:
    candidate = Path(path).resolve()
    try:
        candidate.relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("Local product artifacts must remain inside the current working directory") from exc
    return candidate


def _pdf(text: str) -> bytes:
    """Create a compact, dependency-free, one-page PDF from ASCII-safe text."""
    lines = [wrapped for line in text.splitlines() for wrapped in (textwrap.wrap(line.encode("ascii", "replace").decode("ascii"), width=78) or [""])]
    commands = ["BT", "/F1 11 Tf", "54 760 Td", "14 TL"]
    for line in lines[:45]:
        commands.append("(" + line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ") Tj")
        commands.append("T*")
    commands.append("ET")
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        "<< /Length %d >>\nstream\n%s\nendstream" % (len("\n".join(commands).encode()), "\n".join(commands)),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, value in enumerate(objects, 1):
        offsets.append(len(output)); output.extend(f"{index} 0 obj\n{value}\nendobj\n".encode())
    xref = len(output)
    output.extend(f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n".encode())
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    output.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def export_executive_summary(campaign_root: str, campaign_id: str, output_root: str = "artifacts/exports") -> dict[str, str]:
    campaign = inspect_campaign(campaign_root, campaign_id)
    report = build_campaign_report(campaign["campaign_dir"])
    run = report["run"] or {}
    draft, metadata = report["draft"], report["campaign"]
    lines = [
        "# AdversaryFlow Executive Summary",
        "", f"Campaign: {campaign_id}", f"Status: {metadata.get('status', 'awaiting-approval')}",
        f"Objective: {draft['objective']}", f"Target: {draft['target']}",
        "", "## Outcome", f"Behavior success: {run.get('behavior_success', 'not run')}",
        f"Detection gaps: {run.get('detection_gap_count', 0)}",
        "", "## Decision", "This is an authorized local synthetic validation. It does not establish production detection coverage.",
    ]
    output = _workspace_path(output_root); output.mkdir(parents=True, exist_ok=True)
    markdown = output / f"{campaign_id}-executive-summary.md"
    pdf = output / f"{campaign_id}-executive-summary.pdf"
    markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    pdf.write_bytes(_pdf("\n".join(line.lstrip("# ") for line in lines)))
    return {"markdown": str(markdown), "pdf": str(pdf)}


def update_campaign_tags(campaign_root: str, campaign_id: str, tags: list[str]) -> dict[str, Any]:
    if not isinstance(tags, list) or len(tags) > 12:
        raise ValueError("tags must be a list with at most 12 entries")
    cleaned = sorted({tag.strip().lower() for tag in tags if isinstance(tag, str) and tag.strip()})
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", tag) for tag in cleaned):
        raise ValueError("tags use lowercase letters, numbers, hyphens, or underscores only")
    directory = Path(inspect_campaign(campaign_root, campaign_id)["campaign_dir"])
    metadata_path = directory / "metadata.json"; metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["tags"] = cleaned; metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"campaign_id": campaign_id, "tags": cleaned}


def update_campaign_archive(campaign_root: str, campaign_id: str, owner: str, retention_days: int) -> dict[str, Any]:
    if not isinstance(owner, str) or not (cleaned_owner := owner.strip()) or len(cleaned_owner) > 100:
        raise ValueError("owner must be a non-empty name of at most 100 characters")
    if not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
        raise ValueError("retention_days must be an integer between 1 and 3650")
    directory = Path(inspect_campaign(campaign_root, campaign_id)["campaign_dir"])
    metadata_path = directory / "metadata.json"; metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update({"owner": cleaned_owner, "retention_days": retention_days, "retention_review_due": datetime.now(timezone.utc).date().isoformat()})
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"campaign_id": campaign_id, "owner": cleaned_owner, "retention_days": retention_days}


def search_campaign_archive(campaign_root: str, query: str = "", tag: str = "") -> list[dict[str, Any]]:
    needle, required_tag = query.strip().lower(), tag.strip().lower()
    results = []
    for metadata in list_campaigns(campaign_root):
        campaign = inspect_campaign(campaign_root, metadata["campaign_id"])
        draft = campaign.get("draft", {})
        text = " ".join([metadata["campaign_id"], str(draft.get("actor", "")), str(draft.get("objective", "")), *metadata.get("tags", [])]).lower()
        if (not needle or needle in text) and (not required_tag or required_tag in metadata.get("tags", [])):
            results.append({"campaign_id": metadata["campaign_id"], "status": metadata.get("status"), "tags": metadata.get("tags", []), "owner": metadata.get("owner"), "retention_days": metadata.get("retention_days"), "actor": draft.get("actor"), "objective": draft.get("objective"), "created_at": metadata.get("created_at")})
    return results


def read_roe_editor(roe_path: str, history_root: str = "artifacts/roe-history") -> dict[str, Any]:
    path = _workspace_path(roe_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    RulesOfEngagement.from_mapping(raw)
    history = _workspace_path(history_root) / "history.json"
    entries = json.loads(history.read_text(encoding="utf-8")) if history.exists() else []
    return {"roe": raw, "history": entries[-20:]}


def save_roe_editor(roe_path: str, data: dict[str, Any], editor: str, history_root: str = "artifacts/roe-history") -> dict[str, Any]:
    path = _workspace_path(roe_path)
    candidate = {key: data[key] for key in ("engagement_name", "operator_name", "approver_name", "approved_targets", "excluded_targets", "environment", "dry_run", "allowed_actions") if key in data}
    RulesOfEngagement.from_mapping(candidate)
    if not isinstance(editor, str) or not editor.strip() or len(editor.strip()) > 100:
        raise ValueError("editor must be a non-empty name of at most 100 characters")
    history_dir = _workspace_path(history_root); history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snapshot = history_dir / f"roe-{stamp}.yaml"
    snapshot.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    path.write_text(yaml.safe_dump(candidate, sort_keys=False), encoding="utf-8")
    history_path = history_dir / "history.json"
    entries = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    entries.append({"saved_at": stamp, "editor": editor.strip(), "previous": str(snapshot), "engagement_name": candidate["engagement_name"]})
    history_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return {"saved": str(path), "history_entry": entries[-1], "roe": candidate}
