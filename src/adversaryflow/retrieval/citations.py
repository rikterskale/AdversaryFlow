from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from adversaryflow.models import (
    CitationClaim,
    CitationEdge,
    CitationGraph,
    CitationSource,
    GroundedClaim,
    SourceDocument,
)

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{1,}", re.IGNORECASE)


def _tokens(text: str) -> set[str]:
    stop = {
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "using",
        "used",
        "actor",
        "group",
        "technique",
    }
    return {token.casefold() for token in _TOKEN_RE.findall(text) if token.casefold() not in stop}


def lexical_support(claim: GroundedClaim, text: str) -> float:
    claim_tokens = _tokens(claim.text)
    if not claim_tokens:
        return 0.0
    overlap = len(claim_tokens & _tokens(text)) / len(claim_tokens)
    # Mentioning a technique ID does not, by itself, support the surrounding
    # proposition. Exact ATT&CK relationships are evaluated separately.
    return overlap


class CitationGraphBuilder:
    def __init__(self, documents: list[SourceDocument]) -> None:
        self.documents = documents
        self._documents_by_url: dict[str, SourceDocument] = {}
        self._sources: dict[str, CitationSource] = {}
        self._claims: dict[str, CitationClaim] = {}
        self._edges: dict[tuple[str, str], CitationEdge] = {}
        self._claim_ids_by_source: defaultdict[str, set[str]] = defaultdict(set)
        for document in documents:
            for url in {
                str(document.source.url),
                str(document.source.final_url or document.source.url),
            }:
                self._documents_by_url[url.rstrip("/")] = document
            source_id = self._source_id(str(document.source.final_url or document.source.url))
            self._sources[source_id] = CitationSource(
                source_id=source_id,
                url=str(document.source.final_url or document.source.url),
                title=document.source.title,
                domain=document.source.domain,
                tier=document.source.tier,
                validated=document.source.validated,
                content_sha256=document.source.content_sha256,
            )

    @staticmethod
    def _source_id(url: str) -> str:
        return f"src-{hashlib.sha256(url.rstrip('/').encode()).hexdigest()[:16]}"

    @staticmethod
    def _claim_id(node_name: str, claim: GroundedClaim) -> str:
        if claim.claim_id:
            return claim.claim_id
        value = f"{node_name}:{claim.category}:{claim.text}".encode()
        return f"claim-{hashlib.sha256(value).hexdigest()[:16]}"

    def _best_chunk(self, claim: GroundedClaim, document: SourceDocument) -> tuple[str, str, float]:
        best_text = ""
        best_chunk = ""
        best_score = 0.0
        for chunk in document.chunks:
            score = lexical_support(claim, chunk.text)
            if score > best_score:
                best_text = chunk.text
                best_chunk = chunk.chunk_id
                best_score = score
        return best_text[:1_200], best_chunk, best_score

    def add_claims(self, node_name: str, claims: list[GroundedClaim]) -> None:
        for claim in claims:
            claim_id = self._claim_id(node_name, claim)
            self._claims[claim_id] = CitationClaim(
                claim_id=claim_id,
                text=claim.text,
                category=claim.category,
                node_name=node_name,
                confidence=claim.confidence,
                technique_ids=claim.technique_ids,
            )
            model_excerpts = {
                str(item.source_url).rstrip("/"): item for item in claim.supporting_excerpts
            }
            for source_url in claim.source_urls:
                normalized = str(source_url).rstrip("/")
                document = self._documents_by_url.get(normalized)
                if document is None:
                    continue
                final_url = str(document.source.final_url or document.source.url)
                source_id = self._source_id(final_url)
                supplied = model_excerpts.get(normalized)
                if supplied:
                    excerpt = supplied.excerpt[:1_200]
                    chunk_id = supplied.chunk_id
                    score = lexical_support(claim, excerpt)
                    method = "model_excerpt"
                else:
                    excerpt, chunk_id, score = self._best_chunk(claim, document)
                    method = "lexical_match"
                edge = CitationEdge(
                    claim_id=claim_id,
                    source_id=source_id,
                    source_url=final_url,
                    excerpt=excerpt,
                    chunk_id=chunk_id,
                    support_score=round(score, 4),
                    support_method=method,
                )
                self._edges[(claim_id, source_id)] = edge
                self._claim_ids_by_source[final_url].add(claim_id)

    def build(self) -> CitationGraph:
        return CitationGraph(
            sources=list(self._sources.values()),
            claims=list(self._claims.values()),
            edges=list(self._edges.values()),
        )

    def source_claims(self) -> dict[str, list[str]]:
        return {url: sorted(ids) for url, ids in self._claim_ids_by_source.items()}
