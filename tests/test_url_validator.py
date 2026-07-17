import socket

import httpx
import pytest

from adversaryflow.models import SourceRecord, SourceTier
from adversaryflow.retrieval.url_validator import URLValidator


def _record(url: str = "https://example.com/report") -> SourceRecord:
    return SourceRecord(url=url, title="Report", domain="example.com", tier=SourceTier.FIRST_PARTY)


@pytest.mark.asyncio
async def test_private_resolution_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    def private_address(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", private_address)
    validator = URLValidator(allowed_domains={"example.com"})

    result = await validator.validate(_record())

    assert not result.validated
    assert result.validation_error == "Host resolved to a non-public IP"


@pytest.mark.asyncio
async def test_fetch_pins_validated_address_and_preserves_host_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    async def public_ip(host: str) -> list[str]:
        assert host == "example.com"
        return ["203.0.113.9"]

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["host"] = request.headers["host"]
        seen["sni"] = request.extensions["sni_hostname"]
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"ok")

    validator = URLValidator(
        allowed_domains={"example.com"}, transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr(validator, "_resolve_public_ips", public_ip)

    result = await validator.fetch(_record())

    assert result.record.validated
    assert seen == {
        "url": "https://203.0.113.9/report",
        "host": "example.com",
        "sni": "example.com",
    }


@pytest.mark.asyncio
async def test_redirect_destination_is_validated_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def addresses(host: str) -> list[str]:
        calls.append(host)
        return ["203.0.113.9"] if host == "example.com" else []

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/metadata"})

    validator = URLValidator(
        allowed_domains={"example.com"}, transport=httpx.MockTransport(handler)
    )
    monkeypatch.setattr(validator, "_resolve_public_ips", addresses)

    result = await validator.validate(_record())

    assert not result.validated
    assert result.validation_error == "URL or redirect is outside the allowlist"
    assert calls == ["example.com"]
