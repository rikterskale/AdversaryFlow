from __future__ import annotations

from typing import Literal

from pydantic import Field

from adversaryflow.models import (
    ExerciseInject,
    GroundedClaim,
    ProcedureStep,
    StrictModel,
    TechniqueEvidence,
)


class ActorIdentityOutput(StrictModel):
    canonical_name: str
    attack_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "medium"
    ambiguity_notes: list[str] = Field(default_factory=list)
    queries: list[str] = Field(default_factory=list)


class AttackExtractionOutput(StrictModel):
    techniques: list[TechniqueEvidence] = Field(default_factory=list)
    software: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class AdvisoryObservation(StrictModel):
    summary: str
    published_at: str | None = None
    source_urls: list[str] = Field(default_factory=list)


class AdvisoryExtractionOutput(StrictModel):
    observations: list[AdvisoryObservation] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class DetectionFinding(StrictModel):
    name: str
    product: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    telemetry_requirements: list[str] = Field(default_factory=list)
    source_urls: list[str] = Field(default_factory=list)


class DetectionExtractionOutput(StrictModel):
    detections: list[DetectionFinding] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class DossierSynthesisOutput(StrictModel):
    techniques: list[TechniqueEvidence] = Field(default_factory=list)
    software: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    excluded_techniques: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class EnvironmentFitOutput(StrictModel):
    applicable_surfaces: list[str] = Field(default_factory=list)
    excluded_surfaces: list[str] = Field(default_factory=list)
    feasible_technique_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class RoeTranslationOutput(StrictModel):
    mandatory_controls: list[str] = Field(default_factory=list)
    prohibited_actions: list[str] = Field(default_factory=list)
    safe_equivalents: list[str] = Field(default_factory=list)
    approval_requirements: list[str] = Field(default_factory=list)


class TelemetryMappingOutput(StrictModel):
    telemetry: list[str] = Field(default_factory=list)
    collection_gaps: list[str] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)


class CandidateStep(StrictModel):
    phase: str
    objective: str
    technique_ids: list[str] = Field(default_factory=list)
    action_summary: str
    safe_equivalent: str
    rationale: str = ""
    source_urls: list[str] = Field(default_factory=list)


class PathCandidateOutput(StrictModel):
    name: str
    strategy: str = ""
    steps: list[CandidateStep] = Field(default_factory=list)
    tradeoffs: list[str] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class PathAdjudicationOutput(StrictModel):
    selected: str
    rationale: str
    sequence: list[CandidateStep] = Field(default_factory=list)
    rejected_elements: list[str] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


class FinalCompositionOutput(StrictModel):
    executive_summary: str
    assumptions: list[str] = Field(default_factory=list)
    metrics: list[str] = Field(default_factory=list)
    attack_path: list[ProcedureStep] = Field(default_factory=list)
    injects: list[ExerciseInject] = Field(default_factory=list)
    claims: list[GroundedClaim] = Field(default_factory=list)


NODE_SCHEMAS = {
    "actor_identity": ActorIdentityOutput,
    "attack_extraction": AttackExtractionOutput,
    "advisory_extraction": AdvisoryExtractionOutput,
    "detection_extraction": DetectionExtractionOutput,
    "dossier_synthesis": DossierSynthesisOutput,
    "environment_fit": EnvironmentFitOutput,
    "roe_translation": RoeTranslationOutput,
    "telemetry_mapping": TelemetryMappingOutput,
    "path_candidate_a": PathCandidateOutput,
    "path_candidate_b": PathCandidateOutput,
    "path_adjudication": PathAdjudicationOutput,
    "final_composition": FinalCompositionOutput,
}
