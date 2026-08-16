"""Local product features built on persisted campaign artifacts."""

import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .adapters import adapter_readiness
from .catalog import load_catalog_document, validate_catalog_document
from .emulation import load_catalog


def _root(path: str | Path) -> Path:
    candidate = Path(path).resolve()
    try:
        candidate.relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("Product artifacts must remain inside the current working directory") from exc
    return candidate


def _slug(value: str, label: str = "name") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise ValueError(f"{label} must use lowercase letters, numbers, hyphens, or underscores")
    return value


def save_campaign_template(name: str, actor: str, objective: str, target: str = "local-lab", platform: str = "linux", root: str = "artifacts/templates") -> dict[str, Any]:
    name = _slug(name, "template name")
    values = {"name": name, "actor": actor.strip(), "objective": objective.strip(), "target": target.strip(), "platform": platform.strip(), "created_at": datetime.now(timezone.utc).isoformat(), "boundary": "Template only; review and approval remain required."}
    if not values["actor"] or not values["objective"] or not values["target"]:
        raise ValueError("actor, objective, and target must be non-empty")
    directory = _root(root); directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"
    path.write_text(json.dumps(values, indent=2), encoding="utf-8")
    return {"saved": str(path), **values}


def list_campaign_templates(root: str = "artifacts/templates") -> list[dict[str, Any]]:
    directory = _root(root)
    if not directory.exists():
        return []
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))]


def schedule_retest(name: str, template: str, cadence_days: int, root: str = "artifacts/schedules") -> dict[str, Any]:
    name = _slug(name, "schedule name")
    if not isinstance(cadence_days, int) or not 1 <= cadence_days <= 3650:
        raise ValueError("cadence_days must be an integer between 1 and 3650")
    values = {"name": name, "template": _slug(template, "template"), "cadence_days": cadence_days, "created_at": datetime.now(timezone.utc).isoformat(), "next_review_at": (datetime.now(timezone.utc) + timedelta(days=cadence_days)).isoformat(), "status": "planned", "boundary": "Scheduled review plan only; no automatic campaign execution."}
    directory = _root(root); directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"; path.write_text(json.dumps(values, indent=2), encoding="utf-8")
    return {"saved": str(path), **values}


def import_detection_rules(source: str, output: str = "artifacts/detection-rules") -> dict[str, Any]:
    path = Path(source)
    raw = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in raw.splitlines() if line.strip()]
    rules = data.get("rules", []) if isinstance(data, dict) else data
    if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
        raise ValueError("Detection rule import must contain a list of JSON objects")
    normalized = []
    for index, rule in enumerate(rules, 1):
        normalized.append({"rule_id": str(rule.get("rule_id") or rule.get("id") or f"imported-{index}"), "name": str(rule.get("name") or rule.get("title") or f"Imported rule {index}"), "technique_id": rule.get("technique_id") or rule.get("technique"), "ability_id": rule.get("ability_id"), "enabled": bool(rule.get("enabled", True)), "source": str(path)})
    directory = _root(output); directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "rules.json"
    payload = {"schema": "ADVERSARYFLOW-DETECTION-RULES-1", "imported_at": datetime.now(timezone.utc).isoformat(), "rules": normalized, "boundary": "Imported rules are scored locally only; no vendor rule is deployed."}
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"output": str(destination), "rule_count": len(normalized), "boundary": payload["boundary"]}


def score_detection_rules(campaign_root: str, rules_path: str) -> dict[str, Any]:
    rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    imported = rules.get("rules", [])
    detected = set()
    for campaign_path in _root(campaign_root).glob("campaign-*/metadata.json"):
        metadata = json.loads(campaign_path.read_text(encoding="utf-8"))
        run_dir = metadata.get("run_dir")
        report_path = Path(str(run_dir)) / "telemetry-gap-report.json" if run_dir else None
        if report_path and report_path.is_file():
            for result in json.loads(report_path.read_text(encoding="utf-8")).get("results", []):
                if result.get("telemetry_status") == "detected":
                    detected.add((result.get("technique_id"), result.get("ability_id")))
    scored = [{**rule, "matched": (rule.get("technique_id"), rule.get("ability_id")) in detected} for rule in imported]
    return {"schema": "ADVERSARYFLOW-DETECTION-SCORE-1", "rules": scored, "summary": {"rules": len(scored), "matched": sum(item["matched"] for item in scored), "unmatched": sum(not item["matched"] for item in scored)}, "boundary": "Read-only local scoring; no rule was deployed."}


def retention_preview(campaign_root: str, as_of: datetime | None = None) -> dict[str, Any]:
    now = as_of or datetime.now(timezone.utc); candidates = []
    for path in _root(campaign_root).glob("campaign-*/metadata.json"):
        metadata = json.loads(path.read_text(encoding="utf-8")); days = metadata.get("retention_days")
        if not isinstance(days, int):
            continue
        created = datetime.fromisoformat(str(metadata.get("created_at")).replace("Z", "+00:00"))
        if created + timedelta(days=days) <= now:
            candidates.append({"campaign_id": metadata.get("campaign_id"), "directory": str(path.parent), "retention_days": days, "retention_due": (created + timedelta(days=days)).isoformat()})
    return {"schema": "ADVERSARYFLOW-RETENTION-1", "eligible": candidates, "count": len(candidates), "boundary": "Preview only; cleanup requires explicit confirmation."}


def cleanup_retention(campaign_root: str, confirm: bool = False) -> dict[str, Any]:
    if not confirm:
        raise PermissionError("Retention cleanup requires explicit confirmation")
    preview = retention_preview(campaign_root); removed = []
    for item in preview["eligible"]:
        directory = Path(item["directory"]); 
        if directory.parent == _root(campaign_root).resolve() and directory.name.startswith("campaign-"):
            import shutil
            shutil.rmtree(directory); removed.append(item["campaign_id"])
    return {"removed": removed, "count": len(removed), "boundary": "Only retention-eligible local campaign directories were removed."}


def branch_campaign(campaign_root: str, source_campaign_id: str, branch_name: str) -> dict[str, Any]:
    source = _root(campaign_root) / source_campaign_id
    if not source.is_dir() or not source.name.startswith("campaign-"):
        raise FileNotFoundError(f"Campaign not found: {source_campaign_id}")
    branch_id = f"campaign-{_slug(branch_name, 'branch name')}"
    destination = _root(campaign_root) / branch_id
    if destination.exists():
        raise FileExistsError(f"Campaign branch already exists: {branch_id}")
    shutil.copytree(source, destination)
    metadata_path = destination / "metadata.json"; metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update({"campaign_id": branch_id, "status": "awaiting-approval", "branch_of": source_campaign_id, "branch_created_at": datetime.now(timezone.utc).isoformat()})
    for name in ("approval.json", "rejection.json", "cancellation.json"):
        (destination / name).unlink(missing_ok=True)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {"campaign_id": branch_id, "branch_of": source_campaign_id, "status": metadata["status"], "directory": str(destination), "boundary": "Branch is a new review draft; prior approval was not copied."}


def coverage_trends(campaign_root: str) -> dict[str, Any]:
    points: dict[str, dict[str, int]] = {}
    for path in _root(campaign_root).glob("campaign-*/metadata.json"):
        metadata = json.loads(path.read_text(encoding="utf-8")); day = str(metadata.get("created_at", "unknown"))[:10]
        row = points.setdefault(day, {"campaigns": 0, "detections": 0, "gaps": 0})
        row["campaigns"] += 1
        run_dir = metadata.get("run_dir"); report = Path(str(run_dir)) / "telemetry-gap-report.json" if run_dir else None
        if report and report.is_file():
            for result in json.loads(report.read_text(encoding="utf-8")).get("results", []):
                row["detections"] += result.get("telemetry_status") == "detected"
                row["gaps"] += result.get("outcome") != "detection_fired"
    return {"schema": "ADVERSARYFLOW-COVERAGE-TRENDS-1", "points": [{"date": day, **points[day]} for day in sorted(points)], "boundary": "Read-only local campaign trend summary."}


def author_catalog(source: str, output: str, name: str, version: str) -> dict[str, Any]:
    raw, _ = load_catalog_document(source, require_governance=False)
    raw["governance"] = {"name": _slug(name, "catalog name"), "version": version, "status": "active"}
    validate_catalog_document(raw, output, require_governance=True)
    destination = _root(output); destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    return {"output": str(destination), "name": name, "version": version, "ability_count": len(raw["abilities"]), "boundary": "Catalog draft is validated locally and requires normal release review."}


def adapter_compatibility(catalog: str, adapters: tuple[str, ...] = ("local-synthetic", "local-behavioral", "idpt-local")) -> dict[str, Any]:
    abilities = load_catalog(catalog)
    return {"catalog": str(catalog), "adapters": [adapter_readiness(abilities, name) for name in adapters], "boundary": "Read-only compatibility discovery; no adapter was executed."}
