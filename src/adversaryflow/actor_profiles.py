"""Actor-agnostic, fixture-only defensive validation profiles."""

import json
import re
from pathlib import Path
from typing import Any

from .ctid import create_fixture_bundle, fixtures


PHASES = ("baseline", "fixture-replay", "detection-review", "control-improvement", "retest", "archive-and-training")


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
    fixture_ids = _list(data.get("fixture_ids"), "fixture_ids")
    allowed = {item["id"] for item in fixtures()["fixtures"]}
    if not set(fixture_ids).issubset(allowed):
        raise ValueError("profile may select only pre-registered benign fixtures")
    profile = {"name": name, "actor": actor.strip(), "aliases": _list(data.get("aliases", [actor.strip()]), "aliases"), "sources": _list(data.get("sources"), "sources"), "technique_ids": _list(data.get("technique_ids"), "technique_ids"), "fixture_ids": fixture_ids, "phases": list(PHASES), "boundary": "fixture-only; no phishing, authentication, credential, endpoint, cloud, network, or target action"}
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
    profile = get_profile(name, root); catalog = {item["id"]: item for item in fixtures()["fixtures"]}
    selected = [catalog[item] for item in profile["fixture_ids"]]
    return {"profile": profile, "coverage": [{"fixture_id": item["id"], "technique_id": item["technique_id"], "source": item["source"], "expected_detection": item["expected_detection"], "rule_guidance": item["rule_guidance"]} for item in selected], "phases": list(PHASES), "next": "Create the fixture bundle, replay it only through an approved lab path, assess observed detections, then retest gaps."}


def run_profile(name: str, retest_of: str | None = None, root: str | Path = "artifacts/actor-profiles") -> dict[str, Any]:
    profile = get_profile(name, root)
    return create_fixture_bundle(retest_of=retest_of, fixture_ids=profile["fixture_ids"], actor_profile={"name": profile["name"], "actor": profile["actor"], "sources": profile["sources"], "technique_ids": profile["technique_ids"]})
