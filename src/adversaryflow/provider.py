"""AI provider configuration and non-destructive validation."""

import os
import json
import hashlib
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Any

from .ai import AICampaignDraft, CampaignRequest, build_ai_request_prompt
from .emulation import Ability


SUPPORTED_PROVIDERS = {"offline", "openai-compatible"}


class ProviderError(RuntimeError):
    """Safe, user-facing provider failure without secret or response leakage."""


class OpenAICompatiblePlanner:
    def __init__(self, config: "ProviderConfig", timeout: int = 30):
        self.config = config
        self.timeout = timeout
        self.last_request_metadata: dict[str, Any] = {}

    def draft(self, request: CampaignRequest, abilities: tuple[Ability, ...]) -> AICampaignDraft:
        errors = validate_provider_config(self.config)
        if errors:
            raise ProviderError("Provider configuration invalid: " + "; ".join(errors))
        payload = {
            "model": self.config.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": "Return only valid JSON matching the requested schema."},
                {"role": "user", "content": build_ai_request_prompt(request, abilities)},
            ],
            "response_format": {"type": "json_object"},
        }
        endpoint = self.config.endpoint.rstrip("/") + "/chat/completions"
        request_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        started = time.monotonic()
        try:
            raw = json.dumps(payload).encode("utf-8")
            req = Request(endpoint, data=raw, headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"}, method="POST")
            with urlopen(req, timeout=self.timeout) as response:  # nosec B310 - HTTPS-only endpoint validation above.
                response_data = json.load(response)
            response_hash = hashlib.sha256(json.dumps(response_data, sort_keys=True).encode()).hexdigest()
            self.last_request_metadata = {"provider": self.config.name, "model": self.config.model, "endpoint": self.config.endpoint, "request_sha256": request_hash, "response_sha256": response_hash, "duration_ms": round((time.monotonic() - started) * 1000), "status": "success"}
        except HTTPError as exc:
            self.last_request_metadata = {"provider": self.config.name, "model": self.config.model, "endpoint": self.config.endpoint, "request_sha256": request_hash, "duration_ms": round((time.monotonic() - started) * 1000), "status": f"http_{exc.code}"}
            if exc.code == 401:
                raise ProviderError("Provider authentication failed; check ADVERSARYFLOW_API_KEY.") from exc
            if exc.code == 429:
                raise ProviderError("Provider rate limit reached; retry later.") from exc
            raise ProviderError(f"Provider returned HTTP {exc.code}.") from exc
        except (TimeoutError, URLError):
            self.last_request_metadata = {"provider": self.config.name, "model": self.config.model, "endpoint": self.config.endpoint, "request_sha256": request_hash, "duration_ms": round((time.monotonic() - started) * 1000), "status": "unreachable"}
            raise ProviderError("Provider endpoint could not be reached before timeout.") from None
        except json.JSONDecodeError:
            raise ProviderError("Provider returned invalid JSON.") from None
        try:
            content = response_data["choices"][0]["message"]["content"]
            draft_data = json.loads(content)
            return _draft_from_mapping(draft_data)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise ProviderError("Provider response did not contain valid campaign draft JSON.") from exc


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str | None
    endpoint: str | None
    credential_configured: bool
    api_key: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "endpoint": self.endpoint, "credential_configured": self.credential_configured}


def load_provider_config(environ: dict[str, str] | None = None) -> ProviderConfig:
    env = os.environ if environ is None else environ
    name = env.get("ADVERSARYFLOW_PROVIDER", "offline").strip().lower()
    model = env.get("ADVERSARYFLOW_MODEL") or None
    endpoint = env.get("ADVERSARYFLOW_ENDPOINT") or None
    api_key = env.get("ADVERSARYFLOW_API_KEY") or None
    profile_name = env.get("ADVERSARYFLOW_PROFILE")
    if profile_name and profile_name != "offline":
        profile_path = Path(env.get("ADVERSARYFLOW_PROFILE_FILE", "artifacts/providers/profiles.json"))
        if profile_path.exists():
            try:
                profile = json.loads(profile_path.read_text(encoding="utf-8")).get("profiles", {}).get(profile_name, {})
                name = str(profile.get("provider", name))
                model = model or profile.get("model")
                endpoint = endpoint or profile.get("endpoint")
                api_key = api_key or env.get(profile.get("credential_env", "ADVERSARYFLOW_API_KEY"))
            except (OSError, json.JSONDecodeError):
                pass
    credential = bool(api_key)
    return ProviderConfig(name, model, endpoint, credential, api_key)


def _draft_from_mapping(data: dict[str, Any]) -> AICampaignDraft:
    required = {"actor", "target", "objective", "ability_ids", "risk_level", "approval_required", "expected_telemetry", "stop_conditions", "assumptions"}
    if not required.issubset(data) or not isinstance(data["ability_ids"], list):
        raise ValueError("missing required campaign draft fields")
    return AICampaignDraft(
        actor=str(data["actor"]), target=str(data["target"]), objective=str(data["objective"]),
        ability_ids=tuple(map(str, data["ability_ids"])), risk_level=str(data["risk_level"]),
        approval_required=bool(data["approval_required"]), expected_telemetry=tuple(map(str, data["expected_telemetry"])),
        stop_conditions=tuple(map(str, data["stop_conditions"])), assumptions=tuple(map(str, data["assumptions"])),
        source_refs=tuple(map(str, data.get("source_refs", []))),
    )


def validate_provider_config(config: ProviderConfig) -> list[str]:
    errors: list[str] = []
    if config.name not in SUPPORTED_PROVIDERS:
        errors.append(f"Unsupported provider '{config.name}'. Choose offline or openai-compatible.")
    if config.name == "offline" and config.credential_configured:
        errors.append("Offline provider must not be configured with an API key.")
    if config.name == "openai-compatible":
        if not config.endpoint:
            errors.append("ADVERSARYFLOW_ENDPOINT is required for openai-compatible provider.")
        if not config.model:
            errors.append("ADVERSARYFLOW_MODEL is required for openai-compatible provider.")
        if not config.credential_configured:
            errors.append("ADVERSARYFLOW_API_KEY is required for openai-compatible provider.")
        if config.endpoint and urlparse(config.endpoint).scheme != "https":
            errors.append("ADVERSARYFLOW_ENDPOINT must use HTTPS.")
    return errors


def provider_setup_instructions() -> str:
    return (
        "Offline (default): no configuration required.\n"
        "OpenAI-compatible provider (PowerShell):\n"
        "$env:ADVERSARYFLOW_PROVIDER='openai-compatible'\n"
        "$env:ADVERSARYFLOW_ENDPOINT='https://your-approved-endpoint.example/v1'\n"
        "$env:ADVERSARYFLOW_MODEL='your-approved-model'\n"
        "$env:ADVERSARYFLOW_API_KEY='[set in your secret manager or session]'\n"
        "Use 'adversaryflow provider validate' to check configuration without sending a request."
    )
