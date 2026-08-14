"""Read-only campaign-to-detection coverage summaries."""

import json
from pathlib import Path
from typing import Any

from .lifecycle import inspect_campaign, list_campaigns


def coverage_dashboard(campaign_root: str | Path) -> dict[str, Any]:
    techniques: dict[str, dict[str, Any]] = {}
    actors: dict[str, dict[str, Any]] = {}
    campaign_rows = []
    for metadata in list_campaigns(campaign_root):
        campaign_id = str(metadata["campaign_id"])
        campaign = inspect_campaign(campaign_root, campaign_id)
        draft = campaign.get("draft", {})
        actor = str(draft.get("actor", "unknown"))
        actor_row = actors.setdefault(actor, {"actor": actor, "campaigns": 0, "techniques": set(), "detections": 0, "gaps": 0})
        actor_row["campaigns"] += 1
        row = {"campaign_id": campaign_id, "actor": actor, "status": metadata.get("status"), "retest_of": metadata.get("retest_of"), "techniques": [], "detections": 0, "gaps": 0}
        run_dir = metadata.get("run_dir")
        report_path = Path(str(run_dir)) / "telemetry-gap-report.json" if run_dir else None
        if report_path and report_path.is_file():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            for result in report.get("results", []):
                technique = str(result.get("technique_id", "unknown"))
                item = techniques.setdefault(technique, {"technique_id": technique, "executions": 0, "behavior_succeeded": 0, "telemetry_observed": 0, "detections": 0, "gaps": 0, "campaigns": set(), "actors": set()})
                item["executions"] += 1
                item["behavior_succeeded"] += bool(result.get("behavior_success"))
                item["telemetry_observed"] += result.get("telemetry_status") in {"observed", "detected"}
                item["detections"] += result.get("telemetry_status") == "detected"
                item["gaps"] += result.get("outcome") != "detection_fired"
                item["campaigns"].add(campaign_id); item["actors"].add(actor)
                actor_row["techniques"].add(technique)
                actor_row["detections"] += result.get("telemetry_status") == "detected"
                actor_row["gaps"] += result.get("outcome") != "detection_fired"
                row["techniques"].append(technique)
                row["detections"] += result.get("telemetry_status") == "detected"
                row["gaps"] += result.get("outcome") != "detection_fired"
        campaign_rows.append(row)
    technique_rows = []
    for item in techniques.values():
        technique_rows.append({**item, "campaigns": sorted(item["campaigns"]), "actors": sorted(item["actors"])})
    actor_rows = [{**item, "techniques": sorted(item["techniques"])} for item in actors.values()]
    return {
        "schema": "ADVERSARYFLOW-COVERAGE-DASHBOARD-1",
        "summary": {"campaigns": len(campaign_rows), "actors": len(actor_rows), "techniques": len(technique_rows), "detections": sum(item["detections"] for item in technique_rows), "gaps": sum(item["gaps"] for item in technique_rows)},
        "techniques": sorted(technique_rows, key=lambda item: item["technique_id"]),
        "actors": sorted(actor_rows, key=lambda item: item["actor"].casefold()),
        "campaigns": campaign_rows,
        "flow": ["actor", "technique", "ability", "behavior", "telemetry", "detection", "retest"],
    }
