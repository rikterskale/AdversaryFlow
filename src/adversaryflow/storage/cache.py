from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ValidationError

from adversaryflow.models import SourceDocument, SourceRecord
from adversaryflow.storage.common import atomic_write_json, read_json, sha256_json

CACHE_SCHEMA_VERSION = 1


def normalize_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((parsed.scheme.casefold(), f"{host}{port}", path, parsed.query, ""))


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    stale: int = 0
    invalid: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "stale": self.stale,
            "invalid": self.invalid,
        }


class NodeCache:
    def __init__(self, root: Path) -> None:
        self.root = root / "cache" / "nodes"
        self.stats = CacheStats()

    @staticmethod
    def key(
        *,
        name: str,
        provider: str,
        prompt: str,
        schema: type[BaseModel],
        payload: dict[str, Any],
    ) -> str:
        return sha256_json(
            {
                "cache_schema_version": CACHE_SCHEMA_VERSION,
                "name": name,
                "provider": provider,
                "prompt": prompt,
                "response_schema": schema.model_json_schema(),
                "payload": payload,
            }
        )

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str, schema: type[BaseModel]) -> BaseModel | None:
        path = self._path(key)
        if not path.exists():
            self.stats.misses += 1
            return None
        try:
            entry = read_json(path)
            if entry.get("schema_version") != CACHE_SCHEMA_VERSION or entry.get("key") != key:
                raise ValueError("Node cache metadata mismatch")
            parsed = schema.model_validate(entry["output"])
        except (KeyError, ValueError, ValidationError):
            self.stats.invalid += 1
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        return parsed

    def put(self, key: str, *, name: str, provider: str, output: BaseModel) -> None:
        atomic_write_json(
            self._path(key),
            {
                "schema_version": CACHE_SCHEMA_VERSION,
                "key": key,
                "node": name,
                "provider": provider,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "output": output.model_dump(mode="json"),
            },
        )
        self.stats.writes += 1


class SourceCache:
    def __init__(self, root: Path, *, ttl_seconds: int = 86_400) -> None:
        self.root = root / "cache" / "sources"
        self.ttl_seconds = max(0, ttl_seconds)
        self.stats = CacheStats()

    def _url_path(self, normalized_url: str) -> Path:
        key = sha256_json({"url": normalized_url})
        return self.root / "urls" / key[:2] / f"{key}.json"

    def _document_path(self, content_sha256: str) -> Path:
        return self.root / "documents" / content_sha256[:2] / f"{content_sha256}.json"

    def get(
        self,
        record: SourceRecord,
        *,
        accept: Callable[[SourceDocument], bool] | None = None,
    ) -> SourceDocument | None:
        normalized = normalize_url(str(record.url))
        index_path = self._url_path(normalized)
        if not index_path.exists():
            self.stats.misses += 1
            return None
        try:
            index = read_json(index_path)
            cached_at = datetime.fromisoformat(str(index["cached_at"]))
            age = (datetime.now(timezone.utc) - cached_at).total_seconds()
            if age > self.ttl_seconds:
                self.stats.stale += 1
                self.stats.misses += 1
                return None
            content_hash = str(index["content_sha256"])
            document = SourceDocument.model_validate(read_json(self._document_path(content_hash)))
            if document.source.content_sha256 != content_hash:
                raise ValueError("Source content hash mismatch")
            if accept is not None and not accept(document):
                raise ValueError("Cached source no longer satisfies retrieval policy")
        except (KeyError, OSError, ValueError, ValidationError):
            self.stats.invalid += 1
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        return document

    def put(self, document: SourceDocument) -> None:
        content_hash = document.source.content_sha256
        if not content_hash or not document.source.validated:
            return
        normalized = normalize_url(str(document.source.url))
        atomic_write_json(self._document_path(content_hash), document.model_dump(mode="json"))
        atomic_write_json(
            self._url_path(normalized),
            {
                "schema_version": CACHE_SCHEMA_VERSION,
                "url": normalized,
                "content_sha256": content_hash,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        self.stats.writes += 1

    def get_document(self, content_sha256: str) -> SourceDocument | None:
        """Load immutable content by hash without applying URL-cache freshness."""
        try:
            document = SourceDocument.model_validate(
                read_json(self._document_path(content_sha256))
            )
            if document.source.content_sha256 != content_sha256:
                raise ValueError("Source content hash mismatch")
        except (OSError, ValueError, ValidationError):
            self.stats.invalid += 1
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        return document


def cache_inventory(root: Path) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for kind in ("nodes", "sources"):
        location = root / "cache" / kind
        files = [path for path in location.rglob("*.json")] if location.exists() else []
        result[kind] = {
            "files": len(files),
            "bytes": sum(path.stat().st_size for path in files),
        }
    return result


def clear_cache(root: Path, kind: str) -> None:
    targets = ("nodes", "sources") if kind == "all" else (kind,)
    for target in targets:
        location = root / "cache" / target
        if location.exists():
            shutil.rmtree(location)
