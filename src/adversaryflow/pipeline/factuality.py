from __future__ import annotations

import hashlib
from collections import defaultdict

from adversaryflow.models import (
    CitationGraph,
    FactualityFinding,
    FactualityResult,
    GroundedClaim,
    ProcedureStep,
    TechniqueEvidence,
)


class FactualityEvaluator:
    """Validate that claims have sufficiently strong, claim-level evidence.

    This is a lexical evidence-support check, not a semantic entailment engine.
    """

    def __init__(self, *, threshold: float = 1.0, edge_support_threshold: float = 0.5) -> None:
        self.threshold = threshold
        self.edge_support_threshold = edge_support_threshold

    @staticmethod
    def _local_technique_ids(local_attack: dict[str, object]) -> set[str]:
        uses = local_attack.get("uses", {}) if isinstance(local_attack, dict) else {}
        techniques = uses.get("techniques", []) if isinstance(uses, dict) else []
        return {
            str(item.get("external_id"))
            for item in techniques
            if isinstance(item, dict) and item.get("external_id")
        }

    @staticmethod
    def _synthetic_claim_id(prefix: str, text: str) -> str:
        return f"{prefix}-{hashlib.sha256(text.encode()).hexdigest()[:16]}"

    def evaluate(
        self,
        *,
        graph: CitationGraph,
        final_claims: list[GroundedClaim],
        techniques: list[TechniqueEvidence],
        steps: list[ProcedureStep],
        local_attack: dict[str, object],
    ) -> FactualityResult:
        edges_by_claim: defaultdict[str, list] = defaultdict(list)
        for edge in graph.edges:
            edges_by_claim[edge.claim_id].append(edge)
        graph_claims = {claim.claim_id: claim for claim in graph.claims}
        local_ids = self._local_technique_ids(local_attack)

        evaluation_items: list[tuple[str, str, list[str]]] = []
        for claim in final_claims:
            claim_id = claim.claim_id or self._synthetic_claim_id("final", claim.text)
            matching = next(
                (
                    item.claim_id
                    for item in graph.claims
                    if item.text.casefold().strip() == claim.text.casefold().strip()
                ),
                claim_id,
            )
            evaluation_items.append((matching, claim.text, claim.technique_ids))

        for technique in techniques:
            text = (
                f"{technique.technique_id} {technique.name} is associated with the selected actor."
            )
            matching = next(
                (
                    item.claim_id
                    for item in graph.claims
                    if technique.technique_id in item.technique_ids
                ),
                self._synthetic_claim_id("technique", technique.technique_id),
            )
            evaluation_items.append((matching, text, [technique.technique_id]))

        seen_step_ids: set[str] = set()
        for step in steps:
            for technique_id in step.technique_ids:
                if technique_id in seen_step_ids:
                    continue
                seen_step_ids.add(technique_id)
                text = f"The final exercise path uses actor-supported technique {technique_id}."
                matching = next(
                    (item.claim_id for item in graph.claims if technique_id in item.technique_ids),
                    self._synthetic_claim_id("step", technique_id),
                )
                evaluation_items.append((matching, text, [technique_id]))

        deduped: dict[tuple[str, tuple[str, ...]], tuple[str, str, list[str]]] = {}
        for item in evaluation_items:
            deduped[(item[1].casefold(), tuple(sorted(item[2])))] = item
        items = list(deduped.values())
        if not items:
            return FactualityResult(evaluated=False, passed=True)

        findings: list[FactualityFinding] = []
        supported_count = 0
        for claim_id, claim_text, technique_ids in items:
            edges = edges_by_claim.get(claim_id, [])
            good_edges = [
                edge for edge in edges if edge.support_score >= self.edge_support_threshold
            ]
            local_support = bool(technique_ids) and all(item in local_ids for item in technique_ids)
            supported = bool(good_edges) or local_support
            if supported:
                supported_count += 1
            score = max(
                (edge.support_score for edge in good_edges), default=1.0 if local_support else 0.0
            )
            urls = sorted({edge.source_url for edge in good_edges})
            if local_support:
                urls.append("local-att&ck-stix")
            graph_claim = graph_claims.get(claim_id)
            reason = (
                "Supported by validated claim-level evidence."
                if good_edges
                else "Supported by the pinned local ATT&CK relationship."
                if local_support
                else "No validated citation or pinned ATT&CK relationship supports this claim."
            )
            if graph_claim and not edges and not local_support:
                reason = "The claim exists in the graph but has no validated source edge."
            findings.append(
                FactualityFinding(
                    claim_id=claim_id,
                    claim_text=claim_text,
                    supported=supported,
                    reason=reason,
                    source_urls=urls,
                    support_score=round(score, 4),
                )
            )

        total = len(findings)
        score = supported_count / total
        cited = sum(1 for finding in findings if finding.source_urls)
        citation_coverage = cited / total
        unsupported = [finding.claim_text for finding in findings if not finding.supported]
        return FactualityResult(
            evaluated=True,
            passed=score >= self.threshold,
            score=round(score, 4),
            citation_coverage=round(citation_coverage, 4),
            evaluated_claims=total,
            supported_claims=supported_count,
            unsupported_claims=unsupported,
            findings=findings,
        )
