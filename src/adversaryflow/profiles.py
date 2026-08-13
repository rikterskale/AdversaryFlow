"""Non-secret provider profile management."""

import json
import os
import re
from pathlib import Path
from typing import Any


PROFILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
CREDENTIAL_ENV = re.compile(r"[A-Z_][A-Z0-9_]*")


def _profile_path(root: str | Path = "artifacts/providers") -> Path:
    return Path(root) / "profiles.json"


def _policy_path(root: str | Path = "artifacts/providers") -> Path:
    return Path(root) / "policy.json"


def _load(root: str | Path) -> dict[str, Any]:
    path = _profile_path(root)
    if not path.exists():
        return {"active": "offline", "profiles": {"offline": {"provider": "offline", "credential_env": None}}}
    return json.loads(path.read_text(encoding="utf-8"))


def list_profiles(root: str | Path = "artifacts/providers") -> dict[str, Any]:
    data = _load(root)
    return {"active": data.get("active", "offline"), "profiles": {name: {key: value for key, value in profile.items() if key != "api_key"} for name, profile in data.get("profiles", {}).items()}}


def policy_summary(root: str | Path = "artifacts/providers") -> dict[str, Any]:
    """Return the non-secret provider policy, or a clear setup action."""
    path = _policy_path(root)
    if not path.exists():
        return {"configured": False, "version": None, "allowed_profiles": [], "next": "Allow the selected profile with: adversaryflow provider policy allow <profile-name>"}
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
        allowed = policy.get("allowed_profiles", [])
        if not isinstance(allowed, list):
            raise ValueError("allowed_profiles must be a list")
        return {"configured": True, "version": policy.get("version"), "allowed_profiles": allowed, "next": "Review policy before changing provider settings."}
    except (OSError, ValueError, json.JSONDecodeError):
        return {"configured": False, "version": None, "allowed_profiles": [], "next": "Repair artifacts/providers/policy.json before using a hosted provider."}


def allow_profile(name: str, root: str | Path = "artifacts/providers") -> Path:
    """Explicitly allow one saved, non-secret provider profile."""
    profiles = list_profiles(root)["profiles"]
    profile = profiles.get(name)
    if not profile or name == "offline":
        raise KeyError(f"Provider profile not found: {name}")
    allowed = {"name": name, "provider": profile.get("provider"), "endpoint": profile.get("endpoint"), "model": profile.get("model")}
    path = _policy_path(root)
    summary = policy_summary(root)
    existing = summary["allowed_profiles"] if summary["configured"] else []
    remaining = [item for item in existing if item.get("name") != name]
    remaining.append(allowed)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "allowed_profiles": remaining}, indent=2), encoding="utf-8")
    return path


def policy_error(profile_name: str | None, provider: str, endpoint: str | None, model: str | None, root: str | Path = "artifacts/providers") -> str | None:
    """Reject a hosted profile unless its exact settings are policy-approved."""
    if provider == "offline" or not profile_name:
        return None
    summary = policy_summary(root)
    if not summary["configured"]:
        return f"Provider policy is not configured for profile '{profile_name}'."
    for allowed in summary["allowed_profiles"]:
        if allowed == {"name": profile_name, "provider": provider, "endpoint": endpoint, "model": model}:
            return None
    return f"Provider profile '{profile_name}' is not allowed by the active policy."


def activation_summary(name: str | None = None, root: str | Path = "artifacts/providers", environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Describe the active profile and its safe, non-secret next action."""
    data = list_profiles(root)
    selected = name or data["active"]
    if selected == "offline":
        return {"active": "offline", "ready": True, "credential_configured": False, "next": "Offline mode is ready. It creates local drafts and sends no provider request."}
    profile = data["profiles"].get(selected)
    if not profile:
        raise KeyError(f"Provider profile not found: {selected}")
    credential_env = str(profile.get("credential_env") or "ADVERSARYFLOW_API_KEY")
    environment = os.environ if environ is None else environ
    credential_configured = bool(environment.get(credential_env))
    return {
        "active": selected,
        "provider": profile.get("provider"),
        "endpoint": profile.get("endpoint"),
        "model": profile.get("model"),
        "credential_env": credential_env,
        "credential_configured": credential_configured,
        "ready": credential_configured,
        "next": "Run adversaryflow provider validate, then provider test." if credential_configured else f"Set {credential_env} in your shell or secret manager, then run adversaryflow provider validate.",
    }


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
