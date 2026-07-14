from __future__ import annotations

import json

import httpx

from adversaryflow.providers.search import BraveSearchProvider


async def test_brave_search_post_filters_non_allowlisted_results() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Subscription-Token"] == "test-key"
        assert "site%3Aattack.mitre.org" in str(request.url)
        payload = {
            "web": {
                "results": [
                    {
                        "title": "APT29",
                        "url": "https://attack.mitre.org/groups/G0016/",
                        "description": "MITRE ATT&CK group page",
                    },
                    {
                        "title": "Injected result",
                        "url": "https://evil.example/apt29",
                        "description": "Must be excluded",
                    },
                ]
            }
        }
        return httpx.Response(200, content=json.dumps(payload).encode())

    provider = BraveSearchProvider(
        api_key="test-key",
        transport=httpx.MockTransport(handler),
        domain_batch_size=8,
    )
    results = await provider.search(
        query="APT29 ATT&CK",
        allowed_domains={"attack.mitre.org"},
        limit=5,
    )
    assert len(results) == 1
    assert results[0].domain == "attack.mitre.org"
