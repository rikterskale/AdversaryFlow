from pathlib import Path
from uuid import uuid4

import pytest

from adversaryflow.provider import load_provider_config, validate_provider_config
from adversaryflow.profiles import activation_summary, save_profile, use_profile


def test_offline_provider_is_valid_without_secret():
    config = load_provider_config({})
    assert validate_provider_config(config) == []
    assert config.credential_configured is False


def test_hosted_provider_requires_endpoint_model_and_key():
    config = load_provider_config({"ADVERSARYFLOW_PROVIDER": "openai-compatible"})
    errors = validate_provider_config(config)
    assert len(errors) == 3
    assert all("key" not in error.lower() or "required" in error.lower() for error in errors)


def test_provider_status_never_returns_secret_value():
    config = load_provider_config({"ADVERSARYFLOW_PROVIDER": "openai-compatible", "ADVERSARYFLOW_ENDPOINT": "https://example.test/v1", "ADVERSARYFLOW_MODEL": "model", "ADVERSARYFLOW_API_KEY": "secret-value"})
    assert "secret-value" not in str(config.as_dict())
    assert config.credential_configured is True


def test_active_provider_profile_is_loaded_without_environment_selector():
    root = Path("artifacts/test-profiles") / str(uuid4())
    save_profile("approved", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY", root)
    use_profile("approved", root)
    config = load_provider_config({"ADVERSARYFLOW_PROFILE_FILE": str(root / "profiles.json"), "TEAM_AI_KEY": "secret-value"})
    assert config.name == "openai-compatible"
    assert config.endpoint == "https://example.test/v1"
    assert config.model == "model"
    assert config.credential_configured is True


def test_missing_selected_provider_profile_fails_validation():
    config = load_provider_config({"ADVERSARYFLOW_PROFILE": "renamed", "ADVERSARYFLOW_PROFILE_FILE": "artifacts/no-profiles.json"})
    assert validate_provider_config(config) == ["Provider profile 'renamed' was not found."]


def test_profile_activation_summary_is_redacted_and_gives_a_recovery_step():
    root = Path("artifacts/test-profiles") / str(uuid4())
    save_profile("approved", "openai-compatible", "https://example.test/v1", "model", "TEAM_AI_KEY", root)
    use_profile("approved", root)
    missing_key = activation_summary(root=root, environ={})
    assert missing_key["ready"] is False
    assert missing_key["next"] == "Set TEAM_AI_KEY in your shell or secret manager, then run adversaryflow provider validate."
    ready = activation_summary(root=root, environ={"TEAM_AI_KEY": "secret-value"})
    assert ready["ready"] is True
    assert ready["credential_configured"] is True
    assert "secret-value" not in str(ready)
    assert activation_summary(root=root / "no-profile-file", environ={})["active"] == "offline"
    with pytest.raises(KeyError, match="Provider profile not found"):
        activation_summary("missing", root=root, environ={})

