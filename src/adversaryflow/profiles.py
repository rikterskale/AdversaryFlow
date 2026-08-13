"""Non-secret provider profile management."""

import json
from pathlib import Path
from typing import Any


def _profile_path(root: str | Path = "artifacts/providers") -> Path:
    return Path(root) / "profiles.json"


def _load(root: str | Path) -> dict[str, Any]:
    path = _profile_path(root)
    if not path.exists():
        return {"active": "offline", "profiles": {"offline": {"provider": "offline", "credential_env": None}}}
    return json.loads(path.read_text(encoding="utf-8"))


def list_profiles(root: str | Path = "artifacts/providers") -> dict[str, Any]:
    data = _load(root)
    return {"active": data.get("active", "offline"), "profiles": {name: {key: value for key, value in profile.items() if key != "api_key"} for name, profile in data.get("profiles", {}).items()}}


def save_profile(name: str, provider: str, endpoint: str | None, model: str | None, credential_env: str | None, root: str | Path = "artifacts/providers") -> Path:
    if not name or name == "offline":
        raise ValueError("Profile name must be non-empty and not 'offline'")
    data = _load(root)
    data.setdefault("profiles", {})[name] = {"provider": provider, "endpoint": endpoint, "model": model, "credential_env": credential_env or "ADVERSARYFLOW_API_KEY"}
    path = _profile_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def use_profile(name: str, root: str | Path = "artifacts/providers") -> Path:
    data = _load(root)
    if name != "offline" and name not in data.get("profiles", {}):
        raise KeyError(f"Provider profile not found: {name}")
    data["active"] = name
    path = _profile_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def remove_profile(name: str, root: str | Path = "artifacts/providers") -> None:
    data = _load(root)
    if name == "offline":
        raise ValueError("The offline profile cannot be removed")
    data.get("profiles", {}).pop(name, None)
    if data.get("active") == name:
        data["active"] = "offline"
    path = _profile_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
