"""Non-secret provider profile management."""

import json
import re
from pathlib import Path
from typing import Any


PROFILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
CREDENTIAL_ENV = re.compile(r"[A-Z_][A-Z0-9_]*")


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
    if name == "offline" or not PROFILE_NAME.fullmatch(name):
        raise ValueError("Profile name must use 1-64 letters, numbers, hyphens, or underscores and not be 'offline'")
    if provider != "openai-compatible":
        raise ValueError("Profiles currently support only the openai-compatible provider")
    if not endpoint or not endpoint.startswith("https://"):
        raise ValueError("Profile endpoint must use HTTPS")
    if not model or not model.strip():
        raise ValueError("Profile model must be non-empty")
    credential_env = credential_env or "ADVERSARYFLOW_API_KEY"
    if not CREDENTIAL_ENV.fullmatch(credential_env):
        raise ValueError("Credential environment variable must use uppercase letters, numbers, and underscores")
    data = _load(root)
    data.setdefault("profiles", {})[name] = {"provider": provider, "endpoint": endpoint, "model": model, "credential_env": credential_env}
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
