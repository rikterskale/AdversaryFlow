import pytest

from adversaryflow.provider import load_provider_config, validate_provider_config


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

