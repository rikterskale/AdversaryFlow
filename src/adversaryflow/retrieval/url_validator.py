from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass
from datetime import date
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse, urlunparse

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

    async def _resolve_public_ips(self, host: str) -> list[str]:
        if not host:
            return []
        loop = asyncio.get_running_loop()
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM),
        )
        if not infos:
            return []
        resolved: list[str] = []
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
                return []
            if str(ip) not in resolved:
                resolved.append(str(ip))
        return resolved

    @staticmethod
    def _pinned_url(url: str, ip: str) -> str:
        parsed = urlparse(url)
        address = f"[{ip}]" if ":" in ip else ip
        netloc = address if parsed.port is None else f"{address}:{parsed.port}"
        return urlunparse(parsed._replace(netloc=netloc))

    @staticmethod
    def _header_date(value: str | None) -> date | None:
        if not value:
            return None
        try:
            return parsedate_to_datetime(value).date()
        except (TypeError, ValueError, IndexError):
            return None

    async def fetch(self, record: SourceRecord) -> FetchResult:
        current_url = str(record.url)
        try:
            timeout = httpx.Timeout(self.timeout_seconds)
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                headers={"User-Agent": "AdversaryFlow-SourceValidator/0.2.1"},
                transport=self.transport,
            ) as client:
                for _ in range(6):
                    if not url_is_allowlisted(current_url, self.allowed_domains):
                        raise ValueError("URL or redirect is outside the allowlist")
                    parsed = urlparse(current_url)
                    hostname = parsed.hostname or ""
                    resolved_ips = await self._resolve_public_ips(hostname)
                    if not resolved_ips:
                        raise ValueError("Host resolved to a non-public IP")
                    # Connect to the address validated above rather than resolving the
                    # hostname again inside httpx. Preserve Host and SNI so HTTPS
                    # certificate verification remains bound to the original hostname.
                    host_header = hostname
                    if parsed.port is not None:
                        host_header = f"{host_header}:{parsed.port}"
                    async with client.stream(
                        "GET",
                        self._pinned_url(current_url, resolved_ips[0]),
                        headers={"Host": host_header},
                        extensions={"sni_hostname": hostname},
                    ) as response:
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
                                "published_at": record.published_at
                                or self._header_date(response.headers.get("last-modified")),
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
