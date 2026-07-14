from adversaryflow.models import (
    GroundedClaim,
    ProcedureStep,
    SafetyClassification,
    SourceChunk,
    SourceDocument,
    SourceRecord,
    SourceTier,
    TechniqueEvidence,
)
from adversaryflow.pipeline.factuality import FactualityEvaluator
from adversaryflow.retrieval.citations import CitationGraphBuilder


def _document() -> SourceDocument:
    url = "https://attack.mitre.org/groups/G0016/"
    text = "APT29 uses PowerShell technique T1059.001 for command and scripting execution."
    return SourceDocument(
        source=SourceRecord(
            url=url,
            final_url=url,
            title="APT29",
            domain="attack.mitre.org",
            tier=SourceTier.AUTHORITATIVE,
            validated=True,
            content_sha256="a" * 64,
        ),
        text=text,
        chunks=[
            SourceChunk(
                chunk_id="chunk-1",
                source_url=url,
                text=text,
                ordinal=0,
                sha256="b" * 64,
            )
        ],
    )


def _step(technique_id: str) -> ProcedureStep:
    return ProcedureStep(
        sequence=1,
        phase="Execution",
        objective="Validate telemetry",
        technique_ids=[technique_id],
        action_summary="Run a benign telemetry-equivalent test.",
        safe_equivalent="Use an inert test utility.",
        designated_test_asset="LAB-01",
        stop_conditions=["Stop on unexpected impact"],
        cleanup=["Remove test artifact"],
        safety_classification=SafetyClassification.CONTROLLED_EMULATION,
    )


def test_claim_graph_and_factuality_pass() -> None:
    claim = GroundedClaim(
        text="APT29 uses T1059.001 PowerShell.",
        category="technique",
        technique_ids=["T1059.001"],
        source_urls=["https://attack.mitre.org/groups/G0016/"],
    )
    builder = CitationGraphBuilder([_document()])
    builder.add_claims("attack_extraction", [claim])
    graph = builder.build()
    result = FactualityEvaluator().evaluate(
        graph=graph,
        final_claims=[claim],
        techniques=[
            TechniqueEvidence(
                technique_id="T1059.001",
                name="PowerShell",
                rationale="Supported",
                confidence="high",
                source_urls=["https://attack.mitre.org/groups/G0016/"],
            )
        ],
        steps=[_step("T1059.001")],
        local_attack={"resolved": False},
    )
    assert graph.edges
    assert result.passed
    assert result.score == 1.0


def test_factuality_rejects_unsupported_technique() -> None:
    result = FactualityEvaluator().evaluate(
        graph=CitationGraphBuilder([]).build(),
        final_claims=[],
        techniques=[
            TechniqueEvidence(
                technique_id="T9999",
                name="Unsupported",
                rationale="No source",
                confidence="low",
            )
        ],
        steps=[_step("T9999")],
        local_attack={"resolved": False},
    )
    assert not result.passed
    assert result.unsupported_claims
