from __future__ import annotations

import asyncio
import hashlib
import io
import re
from dataclasses import dataclass
from datetime import date, datetime
from html.parser import HTMLParser
from typing import Any

from pypdf import PdfReader

from adversaryflow.models import SourceChunk, SourceDocument, SourceRecord
from adversaryflow.retrieval.allowlist import url_is_allowlisted
from adversaryflow.retrieval.url_validator import URLValidator
from adversaryflow.storage.cache import SourceCache


class _VisibleTextParser(HTMLParser):
    ignored = {"script", "style", "noscript", "svg"}

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in self.ignored:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in self.ignored and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data.strip():
            self.parts.append(data.strip())


@dataclass(slots=True)
class ExtractionBatch:
    documents: list[SourceDocument]
    records: list[SourceRecord]


class SourceExtractor:
    def __init__(
        self,
        *,
        validator: URLValidator,
        max_document_chars: int = 120_000,
        chunk_chars: int = 1_500,
        concurrency: int = 4,
        cache: SourceCache | None = None,
        refresh_cache: bool = False,
    ) -> None:
        self.validator = validator
        self.max_document_chars = max_document_chars
        self.chunk_chars = chunk_chars
        self.concurrency = max(1, concurrency)
        self.cache = cache
        self.refresh_cache = refresh_cache
        self.cache_events: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _normalize(text: str) -> str:
        text = text.replace("\x00", " ")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _decode(self, body: bytes, content_type: str | None) -> str:
        kind = (content_type or "").casefold()
        if "pdf" in kind or body.startswith(b"%PDF"):
            reader = PdfReader(io.BytesIO(body))
            return "\n\n".join((page.extract_text() or "") for page in reader.pages)
        text_like = (
            kind.startswith("text/")
            or "json" in kind
            or "xml" in kind
            or "javascript" in kind
            or not kind
        )
        if not text_like and "html" not in kind:
            raise ValueError(f"Unsupported source content type: {kind or 'unknown'}")
        decoded = body.decode("utf-8", errors="replace")
        if "html" in kind or "<html" in decoded[:1000].casefold():
            parser = _VisibleTextParser()
            parser.feed(decoded)
            return "\n".join(parser.parts)
        return decoded

    @staticmethod
    def _published_at(body: bytes, content_type: str | None) -> date | None:
        """Extract an explicit publication date from common HTML metadata."""
        kind = (content_type or "").casefold()
        if "html" not in kind:
            return None
        text = body.decode("utf-8", errors="replace")[:100_000]
        for tag in re.findall(r"<meta\b[^>]*>", text, flags=re.IGNORECASE):
            attributes = {
                key.casefold(): value
                for key, _, value in re.findall(
                    r"([\w:-]+)\s*=\s*([\"'])(.*?)\2", tag, flags=re.IGNORECASE
                )
            }
            name = attributes.get("property", attributes.get("name", "")).casefold()
            if name not in {
                "article:published_time",
                "datepublished",
                "publishdate",
                "publication_date",
            }:
                continue
            value = attributes.get("content", "").strip().replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(value).date()
            except ValueError:
                try:
                    return date.fromisoformat(value[:10])
                except ValueError:
                    continue
        return None

    def _chunks(self, url: str, text: str) -> list[SourceChunk]:
        paragraphs = [part.strip() for part in text.splitlines() if part.strip()]
        chunks: list[SourceChunk] = []
        current: list[str] = []
        size = 0
        ordinal = 0
        for paragraph in paragraphs:
            if current and size + len(paragraph) + 1 > self.chunk_chars:
                joined = "\n".join(current)
                digest = hashlib.sha256(joined.encode()).hexdigest()
                chunks.append(
                    SourceChunk(
                        chunk_id=f"chunk-{digest[:16]}",
                        source_url=url,
                        text=joined,
                        ordinal=ordinal,
                        sha256=digest,
                    )
                )
                ordinal += 1
                current = []
                size = 0
            current.append(paragraph)
            size += len(paragraph) + 1
        if current:
            joined = "\n".join(current)
            digest = hashlib.sha256(joined.encode()).hexdigest()
            chunks.append(
                SourceChunk(
                    chunk_id=f"chunk-{digest[:16]}",
                    source_url=url,
                    text=joined,
                    ordinal=ordinal,
                    sha256=digest,
                )
            )
        return chunks

    async def extract(self, record: SourceRecord) -> tuple[SourceDocument | None, SourceRecord]:
        url = str(record.url)
        if self.cache and not self.refresh_cache:
            cached = self.cache.get(
                record,
                accept=lambda document: url_is_allowlisted(
                    str(document.source.final_url or document.source.url),
                    self.validator.allowed_domains,
                ),
            )
            if cached is not None:
                self.cache_events[url] = {
                    "url": url,
                    "status": "hit",
                    "content_sha256": cached.source.content_sha256,
                }
                return cached, cached.source
        fetched = await self.validator.fetch(record)
        if not fetched.record.validated:
            self.cache_events[url] = {"url": url, "status": "fetch_failed"}
            return None, fetched.record
        try:
            text = self._normalize(self._decode(fetched.body, fetched.record.content_type))
            text = text[: self.max_document_chars]
            final_url = str(fetched.record.final_url or fetched.record.url)
            chunks = self._chunks(final_url, text)
            updated = fetched.record.model_copy(
                update={
                    "word_count": len(text.split()),
                    "excerpt": fetched.record.excerpt or (text[:500] if text else None),
                    "published_at": fetched.record.published_at
                    or self._published_at(fetched.body, fetched.record.content_type),
                }
            )
            document = SourceDocument(source=updated, text=text, chunks=chunks)
            if self.cache:
                self.cache.put(document)
            self.cache_events[url] = {
                "url": url,
                "status": "refresh" if self.refresh_cache else "miss",
                "content_sha256": updated.content_sha256,
            }
            return document, updated
        except Exception as exc:  # noqa: BLE001 - surfaced in source manifest
            failed = fetched.record.model_copy(
                update={"validated": False, "validation_error": f"Extraction failed: {exc}"[:300]}
            )
            self.cache_events[url] = {"url": url, "status": "extraction_failed"}
            return None, failed

    async def extract_many(self, records: list[SourceRecord]) -> ExtractionBatch:
        self.cache_events = {}
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _one(item: SourceRecord) -> tuple[SourceDocument | None, SourceRecord]:
            async with semaphore:
                return await self.extract(item)

        results = await asyncio.gather(*(_one(record) for record in records)) if records else []
        documents = [document for document, _ in results if document is not None]
        updated_records = [record for _, record in results]
        return ExtractionBatch(documents=documents, records=updated_records)
