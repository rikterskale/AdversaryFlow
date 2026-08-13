import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from uuid import uuid4

import pytest

from adversaryflow.ai import CampaignRequest
from adversaryflow.emulation import load_catalog
from adversaryflow.provider import OpenAICompatiblePlanner, ProviderConfig, ProviderError, load_provider_config, validate_provider_config


def _config():
    return ProviderConfig("openai-compatible", "test-model", "https://example.test/v1", True, "secret")


def test_client_parses_structured_draft():
    body = {"choices": [{"message": {"content": json.dumps({"actor": "APT29", "target": "local-lab", "objective": "test", "ability_ids": [], "risk_level": "Low", "approval_required": True, "expected_telemetry": [], "stop_conditions": ["stop"], "assumptions": []})}}]}
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def __iter__(self): return iter([])
        def read(self): return json.dumps(body).encode()
    with patch("adversaryflow.provider.urlopen", return_value=Response()):
        draft = OpenAICompatiblePlanner(_config()).draft(CampaignRequest("APT29", "local-lab", "test"), load_catalog("content/abilities/catalog.json"))
    assert draft.approval_required is True


def test_client_hides_auth_failure():
    with patch("adversaryflow.provider.urlopen", side_effect=HTTPError("https://example.test", 401, "bad", {}, None)):
        with pytest.raises(ProviderError, match="authentication failed"):
            OpenAICompatiblePlanner(_config()).draft(CampaignRequest("APT29", "local-lab", "test"), ())


@pytest.mark.parametrize(("failure", "message", "status"), [
    (HTTPError("https://example.test", 429, "limited", {}, None), "rate limit", "http_429"),
    (HTTPError("https://example.test", 500, "error", {}, None), "HTTP 500", "http_500"),
    (URLError("unreachable"), "could not be reached", "unreachable"),
])
def test_client_normalizes_nonsecret_provider_failures(failure, message, status):
    planner = OpenAICompatiblePlanner(_config())
    with patch("adversaryflow.provider.urlopen", side_effect=failure):
        with pytest.raises(ProviderError, match=message):
            planner.draft(CampaignRequest("APT29", "local-lab", "test"), ())
    assert planner.last_request_metadata["status"] == status
    assert "secret" not in json.dumps(planner.last_request_metadata).lower()


def test_client_rejects_invalid_config_and_malformed_provider_body():
    invalid = ProviderConfig("openai-compatible", None, None, False)
    with pytest.raises(ProviderError, match="configuration invalid"):
        OpenAICompatiblePlanner(invalid).draft(CampaignRequest("APT29", "local-lab", "test"), ())

    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return b"not-json"

    with patch("adversaryflow.provider.urlopen", return_value=Response()):
        with pytest.raises(ProviderError, match="invalid JSON"):
            OpenAICompatiblePlanner(_config()).draft(CampaignRequest("APT29", "local-lab", "test"), ())


def test_provider_profile_loading_and_validation_recover_without_network():
    root = Path("artifacts") / f"provider-profile-{uuid4()}"
    root.mkdir(parents=True)
    missing = load_provider_config({"ADVERSARYFLOW_PROFILE": "approved", "ADVERSARYFLOW_PROFILE_FILE": str(root / "missing.json")})
    assert "was not found" in missing.profile_error
    broken = root / "broken.json"
    broken.write_text("not-json", encoding="utf-8")
    assert "could not be read" in load_provider_config({"ADVERSARYFLOW_PROFILE_FILE": str(broken)}).profile_error
    profile = root / "profiles.json"
    profile.write_text(json.dumps({"active": "approved", "profiles": {"approved": {"provider": "openai-compatible", "endpoint": "https://example.test/v1", "model": "model", "credential_env": "TEAM_KEY"}}}), encoding="utf-8")
    loaded = load_provider_config({"ADVERSARYFLOW_PROFILE_FILE": str(profile), "TEAM_KEY": "secret"})
    assert loaded.name == "openai-compatible"
    assert loaded.credential_configured is True
    assert validate_provider_config(ProviderConfig("offline", None, None, True)) == ["Offline provider must not be configured with an API key."]
