"""Actor-agnostic, fixture-only defensive validation profiles."""

import json
import re
from pathlib import Path
from typing import Any

from .benign_procedures import catalog as procedure_catalog, run as run_procedures
from .ctid import create_fixture_bundle, fixtures


PHASES = ("baseline", "benign-validation", "detection-review", "control-improvement", "retest", "archive-and-training")


def _root(root: str | Path) -> Path:
    path = Path(root).resolve()
    try:
        path.relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("Actor profiles must remain inside the current working directory") from exc
    path.mkdir(parents=True, exist_ok=True)
    return path


def _profiles_path(root: str | Path) -> Path:
    return _root(root) / "profiles.json"


def _load(root: str | Path) -> dict[str, Any]:
    path = _profiles_path(root)
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"format": "ADVERSARYFLOW-ACTOR-PROFILES-1", "profiles": {}}


def _list(value: object, name: str, maximum: int = 32) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{name} must be a non-empty list of at most {maximum} text entries")
    return sorted({item.strip() for item in value})


def save_profile(data: dict[str, Any], root: str | Path = "artifacts/actor-profiles") -> dict[str, Any]:
    name = data.get("name")
    actor = data.get("actor")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", name):
        raise ValueError("profile name must use lowercase letters, numbers, hyphens, or underscores")
    if not isinstance(actor, str) or not actor.strip() or len(actor.strip()) > 200:
        raise ValueError("actor must be a non-empty name of at most 200 characters")
    fixture_ids = _list(data.get("fixture_ids", []), "fixture_ids") if data.get("fixture_ids") else []
    procedure_ids = _list(data.get("procedure_ids", []), "procedure_ids") if data.get("procedure_ids") else []
    allowed = {item["id"] for item in fixtures()["fixtures"]}
    allowed_procedures = {item["id"] for item in procedure_catalog()["procedures"]}
    if not fixture_ids and not procedure_ids:
        raise ValueError("profile must select at least one benign fixture or procedure")
    if not set(fixture_ids).issubset(allowed):
        raise ValueError("profile may select only pre-registered benign fixtures")
    if not set(procedure_ids).issubset(allowed_procedures):
        raise ValueError("profile may select only pre-registered benign procedures")
    profile = {"name": name, "actor": actor.strip(), "aliases": _list(data.get("aliases", [actor.strip()]), "aliases"), "sources": _list(data.get("sources"), "sources"), "technique_ids": _list(data.get("technique_ids"), "technique_ids"), "fixture_ids": fixture_ids, "procedure_ids": procedure_ids, "phases": list(PHASES), "boundary": "fixed benign procedures and fixtures only; no arbitrary commands, credentials, remote execution, cloud changes, external network contact, or destructive action"}
    stored = _load(root); stored["profiles"][name] = profile; _profiles_path(root).write_text(json.dumps(stored, indent=2), encoding="utf-8")
    return profile


def list_profiles(root: str | Path = "artifacts/actor-profiles") -> list[dict[str, Any]]:
    return list(_load(root)["profiles"].values())


def get_profile(name: str, root: str | Path = "artifacts/actor-profiles") -> dict[str, Any]:
    profile = _load(root)["profiles"].get(name)
    if not profile:
        raise ValueError(f"Actor profile not found: {name}")
    return profile


def plan_profile(name: str, root: str | Path = "artifacts/actor-profiles") -> dict[str, Any]:
    profile = get_profile(name, root); fixture_map = {item["id"]: item for item in fixtures()["fixtures"]}; procedure_map = {item["id"]: item for item in procedure_catalog()["procedures"]}
    coverage = ([{"kind": "fixture", "id": item["id"], "technique_id": item["technique_id"], "source": item["source"], "expected_detection": item["expected_detection"], "rule_guidance": item["rule_guidance"]} for item in (fixture_map[key] for key in profile["fixture_ids"])] + [{"kind": "procedure", "id": item["id"], "technique_id": item["technique_id"], "source": item["source"], "expected_detection": item["expected_detection"], "rule_guidance": item["expected_detection"]} for item in (procedure_map[key] for key in profile["procedure_ids"])])
    return {"profile": profile, "coverage": coverage, "phases": list(PHASES), "next": "Run fixed benign procedures and/or create fixtures, assess observed detections, clean run-owned artifacts, then retest gaps."}


def run_profile(name: str, retest_of: str | None = None, root: str | Path = "artifacts/actor-profiles") -> dict[str, Any]:
    profile = get_profile(name, root)
    actor = {"name": profile["name"], "actor": profile["actor"], "sources": profile["sources"], "technique_ids": profile["technique_ids"]}
    result: dict[str, Any] = {"profile": profile["name"], "retest_of": retest_of}
    if profile["fixture_ids"]: result["fixtures"] = create_fixture_bundle(retest_of=retest_of, fixture_ids=profile["fixture_ids"], actor_profile=actor)
    if profile["procedure_ids"]: result["procedures"] = run_procedures(profile["procedure_ids"], actor_profile=actor, retest_of=retest_of)
    return result
