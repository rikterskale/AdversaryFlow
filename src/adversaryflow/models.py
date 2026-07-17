from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExerciseMode(str, Enum):
    TABLETOP = "tabletop"
    EMULATION_PLAN = "emulation_plan"
    CONTROLLED_VALIDATION = "controlled_validation"


class ScenarioKind(str, Enum):
    TTP_BASED = "ttp_based"
    AD_HOC = "ad_hoc"


class SafetyClassification(str, Enum):
    SAFE_SIMULATION = "safe_simulation"
    CONTROLLED_EMULATION = "controlled_emulation"
    PROHIBITED = "prohibited"


class SourceTier(str, Enum):
    AUTHORITATIVE = "authoritative"
    FIRST_PARTY = "first_party"
    CURATED = "curated"


class ClaimConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EnvironmentProfile(StrictModel):
    name: str
    platforms: list[str] = Field(default_factory=list)
    identity_systems: list[str] = Field(default_factory=list)
    cloud_services: list[str] = Field(default_factory=list)
    security_tools: list[str] = Field(default_factory=list)
    crown_jewels: list[str] = Field(default_factory=list)
    designated_test_assets: list[str] = Field(default_factory=list)
    notes: str | None = None


class RulesOfEngagement(StrictModel):
    authorized_assets: list[str] = Field(default_factory=list)
    authorized_users: list[str] = Field(default_factory=list)
    authorized_phishing_recipients: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    no_real_funds_or_transactions: bool = True
    no_destructive_execution: bool = True
    real_brand_impersonation_requires_written_consent: bool = True
    required_approvals: list[str] = Field(default_factory=list)
    exercise_window: str | None = None


class ScenarioRequest(StrictModel):
    actor: str = Field(min_length=2)
    objective: str = Field(min_length=5)
    scenario_kind: ScenarioKind = ScenarioKind.TTP_BASED
    ad_hoc_scenario: str | None = Field(
        default=None,
        min_length=10,
        description=(
            "Free-form scenario premise for ad hoc exercises that should not be grounded "
            "in a threat actor or ATT&CK TTP dossier."
        ),
    )
    mode: ExerciseMode = ExerciseMode.EMULATION_PLAN
    environment: EnvironmentProfile
    roe: RulesOfEngagement
    post_2020_tradecraft_only: bool = True
    minimum_source_date: date = date(2020, 1, 1)
    max_attack_path_steps: int = Field(default=8, ge=3, le=15)
    output_audience: list[str] = Field(
        default_factory=lambda: ["red_team", "blue_team", "exercise_control"]
    )

    @model_validator(mode="after")
    def validate_request_shape(self) -> "ScenarioRequest":
        if self.mode != ExerciseMode.TABLETOP and not self.environment.designated_test_assets:
            raise ValueError(
                "At least one designated test asset is required for non-tabletop modes"
            )
        if self.scenario_kind == ScenarioKind.AD_HOC and not self.ad_hoc_scenario:
            raise ValueError("ad_hoc_scenario is required when scenario_kind is ad_hoc")
        return self

    @property
    def is_ad_hoc(self) -> bool:
        return self.scenario_kind == ScenarioKind.AD_HOC


class SourceRecord(StrictModel):
    url: HttpUrl
    final_url: HttpUrl | None = None
    title: str
    domain: str
    tier: SourceTier
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    published_at: date | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_sha256: str | None = None
    word_count: int | None = None
    excerpt: str | None = None
    supports_claims: list[str] = Field(default_factory=list)
    validated: bool = False
    validation_error: str | None = None


class SourceChunk(StrictModel):
    chunk_id: str
    source_url: HttpUrl
    text: str
    ordinal: int
    sha256: str


class SourceDocument(StrictModel):
    source: SourceRecord
    text: str
    chunks: list[SourceChunk] = Field(default_factory=list)

    def model_context(self, max_chars: int = 12_000) -> dict[str, Any]:
        selected: list[dict[str, Any]] = []
        used = 0
        for chunk in self.chunks:
            if used >= max_chars:
                break
            remaining = max_chars - used
            text = chunk.text[:remaining]
            if not text:
                continue
            selected.append(
                {
                    "chunk_id": chunk.chunk_id,
                    "text": text,
                    "ordinal": chunk.ordinal,
                }
            )
            used += len(text)
        return {
            "source": self.source.model_dump(mode="json"),
            "chunks": selected,
        }


class SupportingExcerpt(StrictModel):
    source_url: HttpUrl
    excerpt: str
    chunk_id: str | None = None


class GroundedClaim(StrictModel):
    claim_id: str = ""
    text: str = Field(min_length=3)
    category: str = "general"
    confidence: ClaimConfidence = ClaimConfidence.MEDIUM
    technique_ids: list[str] = Field(default_factory=list)
    source_urls: list[HttpUrl] = Field(default_factory=list)
    supporting_excerpts: list[SupportingExcerpt] = Field(default_factory=list)


class CitationSource(StrictModel):
    source_id: str
    url: str
    title: str
    domain: str
    tier: SourceTier
    validated: bool
    content_sha256: str | None = None


class CitationClaim(StrictModel):
    claim_id: str
    text: str
    category: str
    node_name: str
    confidence: ClaimConfidence
    technique_ids: list[str] = Field(default_factory=list)


class CitationEdge(StrictModel):
    claim_id: str
    source_id: str
    source_url: str
    excerpt: str
    chunk_id: str | None = None
    support_score: float = Field(ge=0.0, le=1.0)
    support_method: Literal["model_excerpt", "lexical_match", "local_attack"]


class CitationGraph(StrictModel):
    sources: list[CitationSource] = Field(default_factory=list)
    claims: list[CitationClaim] = Field(default_factory=list)
    edges: list[CitationEdge] = Field(default_factory=list)

    def cited_source_urls(self) -> set[str]:
        return {edge.source_url for edge in self.edges}


class TechniqueEvidence(StrictModel):
    technique_id: str
    name: str
    rationale: str
    confidence: Literal["high", "medium", "low"]
    observed_after_2020: bool | None = None
    source_urls: list[HttpUrl] = Field(default_factory=list)


class ActorIdentity(StrictModel):
    canonical_name: str
    attack_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"
    ambiguity_notes: list[str] = Field(default_factory=list)


class TTPDossier(StrictModel):
    identity: ActorIdentity
    techniques: list[TechniqueEvidence] = Field(default_factory=list)
    software: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    excluded_techniques: list[str] = Field(default_factory=list)
    source_manifest: list[SourceRecord] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class ExpectedObservable(StrictModel):
    source: str
    observable: str
    collection_requirement: str | None = None


class ProcedureStep(StrictModel):
    sequence: int
    phase: str
    objective: str
    technique_ids: list[str]
    action_summary: str
    safe_equivalent: str
    prerequisites: list[str] = Field(default_factory=list)
    designated_test_asset: str | None = None
    required_approvals: list[str] = Field(default_factory=list)
    expected_observables: list[ExpectedObservable] = Field(default_factory=list)
    evidence_to_capture: list[str] = Field(default_factory=list)
    detection_opportunities: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    cleanup: list[str] = Field(default_factory=list)
    safety_classification: SafetyClassification
    assumptions: list[str] = Field(default_factory=list)
    source_urls: list[HttpUrl] = Field(default_factory=list)


class ExerciseInject(StrictModel):
    time_offset: str
    audience: str
    inject: str
    expected_response: str
    success_measure: str


class FactualityFinding(StrictModel):
    claim_id: str
    claim_text: str
    supported: bool
    reason: str
    source_urls: list[str] = Field(default_factory=list)
    support_score: float = Field(ge=0.0, le=1.0)


class FactualityResult(StrictModel):
    """Result of claim-evidence support validation.

    A run with no factual claims is not a successful verification; it is not
    applicable to this gate.
    """

    evaluated: bool = False
    passed: bool = True
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    citation_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    evaluated_claims: int = 0
    supported_claims: int = 0
    unsupported_claims: list[str] = Field(default_factory=list)
    findings: list[FactualityFinding] = Field(default_factory=list)


class QAResult(StrictModel):
    unsupported_claims: list[str] = Field(default_factory=list)
    blocked_items: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    source_validation_passed: bool = False
    factuality_passed: bool = False
    factuality_score: float = Field(default=0.0, ge=0.0, le=1.0)
    citation_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    safety_gate_passed: bool = False
    model_call_count: int = 0
    repair_call_count: int = 0


class ScenarioPack(StrictModel):
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request: ScenarioRequest
    dossier: TTPDossier
    executive_summary: str
    exercise_assumptions: list[str] = Field(default_factory=list)
    attack_path: list[ProcedureStep] = Field(default_factory=list)
    injects: list[ExerciseInject] = Field(default_factory=list)
    metrics: list[str] = Field(default_factory=list)
    source_manifest: list[SourceRecord] = Field(default_factory=list)
    citation_graph: CitationGraph = Field(default_factory=CitationGraph)
    factuality: FactualityResult = Field(default_factory=FactualityResult)
    qa: QAResult = Field(default_factory=QAResult)
    trace: dict[str, Any] = Field(default_factory=dict)
