from __future__ import annotations

import asyncio
import hashlib
import io
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from pypdf import PdfReader

from adversaryflow.models import SourceChunk, SourceDocument, SourceRecord
from adversaryflow.retrieval.url_validator import URLValidator


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
    ) -> None:
        self.validator = validator
        self.max_document_chars = max_document_chars
        self.chunk_chars = chunk_chars
        self.concurrency = max(1, concurrency)

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
        fetched = await self.validator.fetch(record)
        if not fetched.record.validated:
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
                }
            )
            return SourceDocument(source=updated, text=text, chunks=chunks), updated
        except Exception as exc:  # noqa: BLE001 - surfaced in source manifest
            failed = fetched.record.model_copy(
                update={"validated": False, "validation_error": f"Extraction failed: {exc}"[:300]}
            )
            return None, failed

    async def extract_many(self, records: list[SourceRecord]) -> ExtractionBatch:
        semaphore = asyncio.Semaphore(self.concurrency)

        async def _one(item: SourceRecord) -> tuple[SourceDocument | None, SourceRecord]:
            async with semaphore:
                return await self.extract(item)

        results = await asyncio.gather(*(_one(record) for record in records)) if records else []
        documents = [document for document, _ in results if document is not None]
        updated_records = [record for _, record in results]
        return ExtractionBatch(documents=documents, records=updated_records)
