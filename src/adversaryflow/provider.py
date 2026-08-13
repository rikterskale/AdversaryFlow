"""AI provider configuration and non-destructive validation."""

import os
from dataclasses import dataclass
from typing import Any


SUPPORTED_PROVIDERS = {"offline", "openai-compatible"}


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str | None
    endpoint: str | None
    credential_configured: bool

    def as_dict(self) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "endpoint": self.endpoint, "credential_configured": self.credential_configured}


def load_provider_config(environ: dict[str, str] | None = None) -> ProviderConfig:
    env = os.environ if environ is None else environ
    name = env.get("ADVERSARYFLOW_PROVIDER", "offline").strip().lower()
    model = env.get("ADVERSARYFLOW_MODEL") or None
    endpoint = env.get("ADVERSARYFLOW_ENDPOINT") or None
    credential = bool(env.get("ADVERSARYFLOW_API_KEY"))
    return ProviderConfig(name, model, endpoint, credential)


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

