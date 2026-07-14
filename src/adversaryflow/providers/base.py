from __future__ import annotations

from typing import Any, Protocol

from adversaryflow.models import SourceRecord


class LLMProvider(Protocol):
    call_count: int

    async def complete_json(
        self,
        *,
        call_name: str,
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a JSON object for one orchestration node."""


class SearchProvider(Protocol):
    async def search(
        self,
        *,
        query: str,
        allowed_domains: set[str],
        limit: int = 8,
    ) -> list[SourceRecord]:
        """Return allowlist-filtered source candidates."""
