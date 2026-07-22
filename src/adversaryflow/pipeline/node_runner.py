from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from adversaryflow.pipeline.prompts import node_prompt
from adversaryflow.pipeline.schemas import NODE_SCHEMAS
from adversaryflow.providers.base import LLMProvider
from adversaryflow.storage.cache import NodeCache


@dataclass(slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 2.0


class NodeExecutionError(RuntimeError):
    pass


class NodeRunner:
    def __init__(
        self,
        *,
        llm: LLMProvider,
        retry_policy: RetryPolicy | None = None,
        cache: NodeCache | None = None,
        provider_identity: str | None = None,
        refresh_cache: bool = False,
    ) -> None:
        self.llm = llm
        self.retry_policy = retry_policy or RetryPolicy()
        self.cache = cache
        self.provider_identity = provider_identity or (
            f"{type(llm).__module__}.{type(llm).__qualname__}"
        )
        self.refresh_cache = refresh_cache
        self.trace: dict[str, Any] = {}
        self.repair_call_count = 0

    async def run(self, name: str, payload: dict[str, Any]) -> BaseModel:
        schema = NODE_SCHEMAS[name]
        prompt = node_prompt(name, schema)
        cache_key = (
            self.cache.key(
                name=name,
                provider=self.provider_identity,
                prompt=prompt,
                schema=schema,
                payload=payload,
            )
            if self.cache
            else None
        )
        if self.cache and cache_key and not self.refresh_cache:
            cached = self.cache.get(cache_key, schema)
            if cached is not None:
                self.trace[name] = {
                    "status": "success",
                    "schema": schema.__name__,
                    "attempt_count": 0,
                    "attempts": [],
                    "parsed_output": cached.model_dump(mode="json"),
                    "cache": {"status": "hit", "key": cache_key},
                }
                return cached
        attempts: list[dict[str, Any]] = []
        previous_output: dict[str, Any] | None = None
        previous_error: str | None = None

        for attempt in range(1, self.retry_policy.max_attempts + 1):
            started = time.perf_counter()
            call_payload = dict(payload)
            if attempt > 1:
                self.repair_call_count += 1
                call_payload["repair_context"] = {
                    "instruction": (
                        "Repair the previous response so it validates against the supplied JSON "
                        "schema. Preserve supported facts; do not add unsupported claims."
                    ),
                    "validation_error": previous_error,
                    "previous_output": previous_output,
                }
            try:
                raw = await self.llm.complete_json(
                    call_name=name,
                    system_prompt=prompt,
                    user_payload=call_payload,
                )
                previous_output = raw
                parsed = schema.model_validate(raw)
                attempts.append(
                    {
                        "attempt": attempt,
                        "status": "success",
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                        "raw_output": raw,
                    }
                )
                self.trace[name] = {
                    "status": "success",
                    "schema": schema.__name__,
                    "attempt_count": attempt,
                    "attempts": attempts,
                    "parsed_output": parsed.model_dump(mode="json"),
                    "cache": {
                        "status": "refresh" if self.refresh_cache else "miss",
                        "key": cache_key,
                    },
                }
                if self.cache and cache_key:
                    self.cache.put(
                        cache_key,
                        name=name,
                        provider=self.provider_identity,
                        output=parsed,
                    )
                return parsed
            except ValidationError as exc:
                previous_error = str(exc)
                attempts.append(
                    {
                        "attempt": attempt,
                        "status": "schema_error",
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                        "error": previous_error,
                        "raw_output": previous_output,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - preserved in audit trace
                previous_error = f"{type(exc).__name__}: {exc}"
                attempts.append(
                    {
                        "attempt": attempt,
                        "status": "provider_error",
                        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                        "error": previous_error,
                    }
                )

            if attempt < self.retry_policy.max_attempts:
                delay = min(
                    self.retry_policy.base_delay_seconds * (2 ** (attempt - 1)),
                    self.retry_policy.max_delay_seconds,
                )
                await asyncio.sleep(delay)

        self.trace[name] = {
            "status": "failed",
            "schema": schema.__name__,
            "attempt_count": len(attempts),
            "attempts": attempts,
        }
        raise NodeExecutionError(
            f"Node {name!r} failed after {len(attempts)} attempts: {previous_error}"
        )
