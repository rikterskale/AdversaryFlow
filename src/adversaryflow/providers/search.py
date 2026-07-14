from __future__ import annotations

import asyncio
from collections.abc import Iterable
from urllib.parse import urlparse

import httpx

from adversaryflow.models import SourceRecord, SourceTier
from adversaryflow.retrieval.allowlist import url_is_allowlisted


class NullSearchProvider:
    """Search provider used when live retrieval is intentionally disabled."""

    async def search(
        self,
        *,
        query: str,
        allowed_domains: set[str],
        limit: int = 8,
    ) -> list[SourceRecord]:
        return []


class SearchProviderNotConfigured(RuntimeError):
    pass


def _source_tier(domain: str) -> SourceTier:
    authoritative = {
        "attack.mitre.org",
        "cisa.gov",
        "www.cisa.gov",
        "learn.microsoft.com",
        "docs.splunk.com",
        "elastic.co",
        "www.elastic.co",
    }
    curated = {
        "github.com",
        "raw.githubusercontent.com",
        "sigmahq.io",
        "atomicredteam.io",
        "caldera.mitre.org",
    }
    if domain in authoritative or domain.endswith(".gov"):
        return SourceTier.AUTHORITATIVE
    if domain in curated:
        return SourceTier.CURATED
    return SourceTier.FIRST_PARTY


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


class BraveSearchProvider:
    """Allowlist-locked Brave Web Search adapter.

    Query-time `site:` constraints reduce irrelevant retrieval, while post-result URL
    validation remains the actual security boundary.
    """

    endpoint = "https://api.search.brave.com/res/v1/web/search"

    def __init__(
        self,
        *,
        api_key: str,
        timeout_seconds: float = 15.0,
        country: str = "US",
        search_lang: str = "en",
        domain_batch_size: int = 8,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("A Brave Search API key is required")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.country = country
        self.search_lang = search_lang
        self.domain_batch_size = max(1, domain_batch_size)
        self.transport = transport

    async def _search_batch(
        self,
        *,
        query: str,
        domains: list[str],
        count: int,
    ) -> list[dict[str, object]]:
        site_filter = " OR ".join(f"site:{domain}" for domain in domains)
        effective_query = f"({query}) ({site_filter})"
        headers = {
            "Accept": "application/json",
            "X-Subscription-Token": self.api_key,
            "User-Agent": "AdversaryFlow/0.2.1",
        }
        params = {
            "q": effective_query,
            "count": min(max(count, 1), 20),
            "country": self.country,
            "search_lang": self.search_lang,
            "safesearch": "strict",
            "spellcheck": "1",
            "result_filter": "web",
        }
        timeout = httpx.Timeout(self.timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            transport=self.transport,
            headers=headers,
        ) as client:
            response = await client.get(self.endpoint, params=params)
            response.raise_for_status()
            payload = response.json()
        web = payload.get("web", {}) if isinstance(payload, dict) else {}
        results = web.get("results", []) if isinstance(web, dict) else []
        return [item for item in results if isinstance(item, dict)]

    async def search(
        self,
        *,
        query: str,
        allowed_domains: set[str],
        limit: int = 8,
    ) -> list[SourceRecord]:
        domains = sorted(domain.casefold().strip(".") for domain in allowed_domains if domain)
        if not domains or limit <= 0:
            return []

        batches = list(_chunks(domains, self.domain_batch_size))
        raw_groups = await asyncio.gather(
            *(
                self._search_batch(
                    query=query,
                    domains=batch,
                    count=max(limit * 2, 10),
                )
                for batch in batches
            )
        )

        records: list[SourceRecord] = []
        seen: set[str] = set()
        for group in raw_groups:
            for item in group:
                url = str(item.get("url") or "").strip()
                if not url or not url_is_allowlisted(url, allowed_domains):
                    continue
                normalized = url.rstrip("/")
                if normalized in seen:
                    continue
                seen.add(normalized)
                domain = (urlparse(url).hostname or "").casefold()
                title = str(item.get("title") or domain or url)
                excerpt = str(item.get("description") or "").strip() or None
                records.append(
                    SourceRecord(
                        url=url,
                        title=title,
                        domain=domain,
                        tier=_source_tier(domain),
                        excerpt=excerpt,
                    )
                )
                if len(records) >= limit:
                    return records
        return records
