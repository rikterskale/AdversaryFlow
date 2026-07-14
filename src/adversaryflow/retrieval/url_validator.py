from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from adversaryflow.models import SourceRecord
from adversaryflow.retrieval.allowlist import url_is_allowlisted


@dataclass(slots=True)
class FetchResult:
    record: SourceRecord
    body: bytes = b""


class URLValidator:
    def __init__(
        self,
        *,
        allowed_domains: set[str],
        timeout_seconds: float = 10.0,
        max_bytes: int = 2_000_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.allowed_domains = allowed_domains
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.transport = transport

    async def _host_is_public(self, host: str) -> bool:
        if not host:
            return False
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM),
        )
        if not infos:
            return False
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False
        return True

    async def fetch(self, record: SourceRecord) -> FetchResult:
        current_url = str(record.url)
        try:
            timeout = httpx.Timeout(self.timeout_seconds)
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                headers={"User-Agent": "AdversaryFlow-SourceValidator/0.2.1"},
                transport=self.transport,
            ) as client:
                for _ in range(6):
                    if not url_is_allowlisted(current_url, self.allowed_domains):
                        raise ValueError("URL or redirect is outside the allowlist")
                    parsed = urlparse(current_url)
                    if not await self._host_is_public(parsed.hostname or ""):
                        raise ValueError("Host resolved to a non-public IP")
                    async with client.stream("GET", current_url) as response:
                        if response.is_redirect:
                            location = response.headers.get("location")
                            if not location:
                                raise ValueError("Redirect response omitted Location")
                            current_url = urljoin(current_url, location)
                            continue
                        response.raise_for_status()
                        digest = hashlib.sha256()
                        body = bytearray()
                        async for chunk in response.aiter_bytes():
                            body.extend(chunk)
                            digest.update(chunk)
                            if len(body) > self.max_bytes:
                                raise ValueError("Source exceeded maximum validation size")
                        content_type = response.headers.get("content-type", "").split(";", 1)[0]
                        updated = record.model_copy(
                            update={
                                "validated": True,
                                "final_url": current_url,
                                "status_code": response.status_code,
                                "content_type": content_type or None,
                                "content_sha256": digest.hexdigest(),
                                "validation_error": None,
                            }
                        )
                        return FetchResult(record=updated, body=bytes(body))
                raise ValueError("Too many redirects")
        except Exception as exc:  # noqa: BLE001 - retained for reviewer visibility
            failed = record.model_copy(
                update={"validated": False, "validation_error": str(exc)[:300]}
            )
            return FetchResult(record=failed)

    async def validate(self, record: SourceRecord) -> SourceRecord:
        return (await self.fetch(record)).record

    async def validate_many(self, records: list[SourceRecord]) -> list[SourceRecord]:
        if not records:
            return []
        return list(await asyncio.gather(*(self.validate(record) for record in records)))
