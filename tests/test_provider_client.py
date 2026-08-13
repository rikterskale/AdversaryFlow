import json
from unittest.mock import patch

import pytest

from adversaryflow.ai import CampaignRequest
from adversaryflow.emulation import load_catalog
from adversaryflow.provider import OpenAICompatiblePlanner, ProviderConfig, ProviderError


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
    from urllib.error import HTTPError
    with patch("adversaryflow.provider.urlopen", side_effect=HTTPError("https://example.test", 401, "bad", {}, None)):
        with pytest.raises(ProviderError, match="authentication failed"):
            OpenAICompatiblePlanner(_config()).draft(CampaignRequest("APT29", "local-lab", "test"), ())
