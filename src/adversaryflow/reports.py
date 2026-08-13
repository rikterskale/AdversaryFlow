import html
import json
from pathlib import Path
from typing import Any


def build_campaign_report(campaign_dir: str | Path, run_dir: str | Path | None = None) -> dict[str, Any]:
    root = Path(campaign_dir)
    metadata = json.loads((root / "metadata.json").read_text(encoding="utf-8"))
    draft = json.loads((root / "draft.json").read_text(encoding="utf-8"))
    approval_path = root / "approval.json"
    approval = json.loads(approval_path.read_text(encoding="utf-8")) if approval_path.exists() else None
    report: dict[str, Any] = {"campaign": metadata, "draft": draft, "approval": approval, "run": None}
    selected_run = Path(run_dir) if run_dir else (Path(metadata["run_dir"]) if metadata.get("run_dir") else None)
    if selected_run and (selected_run / "telemetry-gap-report.json").exists():
        report["run"] = json.loads((selected_run / "telemetry-gap-report.json").read_text(encoding="utf-8"))
    return report


def write_campaign_reports(campaign_dir: str | Path, run_dir: str | Path | None = None) -> tuple[Path, Path]:
    root = Path(campaign_dir)
    report = build_campaign_report(root, run_dir)
    run = report["run"] or {}
    gaps = run.get("gaps", [])
    gap_lines = [f"- **{item['category']}**: {item['description']}" for item in gaps] or ["- None recorded."]
    lines = [
        f"# AdversaryFlow Campaign Report: {report['campaign']['campaign_id']}",
        "", f"- Actor: {report['draft']['actor']}", f"- Target: {report['draft']['target']}",
        f"- Objective: {report['draft']['objective']}", f"- Status: {report['campaign'].get('status', 'awaiting-approval')}",
        f"- Plan hash: `{report['campaign']['plan_hash']}`", "",
        "## Approval", "", json.dumps(report["approval"] or {"status": "pending"}, indent=2), "",
        "## Results", "", f"- Behavior success: `{run.get('behavior_success', 'not-run')}`",
        f"- Expected telemetry: `{run.get('telemetry_expected', 0)}`", f"- Observed telemetry: `{run.get('telemetry_observed', 0)}`",
        f"- Detection gaps: `{run.get('detection_gap_count', 0)}`", "",
        "## Detection gaps", "", *gap_lines,
        "", "## Safety note", "", "This report describes authorized, local synthetic validation. Behavior success does not prove production detection success.",
    ]
    markdown = root / "campaign-report.md"
    markdown.write_text("\n".join(lines) + "\n", encoding="utf-8")
    html_items = "".join(f"<li><strong>{html.escape(item['category'])}</strong>: {html.escape(item['description'])}</li>" for item in gaps) or "<li>None recorded.</li>"
    html_report = root / "campaign-report.html"
    html_report.write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>AdversaryFlow Campaign Report</title></head><body><h1>AdversaryFlow Campaign Report</h1><p><b>Campaign:</b> {html.escape(report['campaign']['campaign_id'])}</p><p><b>Actor:</b> {html.escape(report['draft']['actor'])}</p><p><b>Objective:</b> {html.escape(report['draft']['objective'])}</p><h2>Results</h2><ul><li>Behavior success: {html.escape(str(run.get('behavior_success', 'not-run')))}</li><li>Detection gaps: {run.get('detection_gap_count', 0)}</li></ul><h2>Detection gaps</h2><ul>{html_items}</ul><p>This report describes authorized, local synthetic validation.</p></body></html>\n", encoding="utf-8")
    return markdown, html_report
