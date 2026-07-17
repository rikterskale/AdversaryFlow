from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from adversaryflow.models import (
    ActorIdentity,
    ExerciseInject,
    ExpectedObservable,
    ProcedureStep,
    QAResult,
    SafetyClassification,
    ScenarioPack,
    ScenarioRequest,
    SourceRecord,
    TTPDossier,
    CitationGraph,
    TechniqueEvidence,
)
from adversaryflow.pipeline.factuality import FactualityEvaluator
from adversaryflow.pipeline.node_runner import NodeRunner, RetryPolicy
from adversaryflow.pipeline.schemas import (
    ActorIdentityOutput,
    AdvisoryExtractionOutput,
    AttackExtractionOutput,
    DetectionExtractionOutput,
    DossierSynthesisOutput,
    EnvironmentFitOutput,
    FinalCompositionOutput,
    PathAdjudicationOutput,
    PathCandidateOutput,
    RoeTranslationOutput,
    TelemetryMappingOutput,
)
from adversaryflow.providers.base import LLMProvider, SearchProvider
from adversaryflow.retrieval.attack_catalog import AttackCatalog
from adversaryflow.retrieval.citations import CitationGraphBuilder
from adversaryflow.retrieval.source_extractor import SourceExtractor
from adversaryflow.retrieval.url_validator import URLValidator
from adversaryflow.safety.policy import SafetyPolicy


class ScenarioOrchestrator:
    def __init__(
        self,
        *,
        llm: LLMProvider,
        search: SearchProvider,
        safety_policy: SafetyPolicy,
        url_validator: URLValidator,
        attack_bundle_path: str | Path | None = None,
        source_extractor: SourceExtractor | None = None,
        retry_policy: RetryPolicy | None = None,
        factuality_evaluator: FactualityEvaluator | None = None,
        fail_on_factuality_error: bool = True,
        require_grounded_dossier: bool = False,
    ) -> None:
        self.llm = llm
        self.search = search
        self.safety_policy = safety_policy
        self.url_validator = url_validator
        self.attack_bundle_path = Path(attack_bundle_path) if attack_bundle_path else None
        self.source_extractor = source_extractor or SourceExtractor(validator=url_validator)
        self.retry_policy = retry_policy or RetryPolicy()
        self.factuality_evaluator = factuality_evaluator or FactualityEvaluator()
        self.fail_on_factuality_error = fail_on_factuality_error
        self.require_grounded_dossier = require_grounded_dossier
        self.trace: dict[str, Any] = {}

    def _local_attack_context(self, actor: str) -> dict[str, Any]:
        if not self.attack_bundle_path or not self.attack_bundle_path.exists():
            return {"available": False, "reason": "No local ATT&CK bundle configured"}
        catalog = AttackCatalog(self.attack_bundle_path)
        group = catalog.resolve_group(actor)
        if not group:
            return {"available": True, "resolved": False}
        return {
            "available": True,
            "resolved": True,
            "group": {
                "name": group.get("name"),
                "aliases": group.get("aliases", []),
                "attack_id": catalog.external_id(group),
            },
            "uses": catalog.uses(group["id"]),
        }

    async def _search_sources(
        self,
        queries: list[str],
    ) -> tuple[list[SourceRecord], list[str]]:
        async def _run(query: str) -> tuple[list[SourceRecord], str | None]:
            try:
                records = await self.search.search(
                    query=query,
                    allowed_domains=self.url_validator.allowed_domains,
                    limit=8,
                )
                return records, None
            except Exception as exc:  # noqa: BLE001 - recorded for reviewer visibility
                return [], f"{query}: {type(exc).__name__}: {exc}"

        results = await asyncio.gather(*(_run(query) for query in queries[:4]))
        records: list[SourceRecord] = []
        errors: list[str] = []
        seen: set[str] = set()
        for group, error in results:
            if error:
                errors.append(error)
            for record in group:
                normalized = str(record.url).rstrip("/")
                if normalized in seen:
                    continue
                seen.add(normalized)
                records.append(record)
        return records, errors

    async def generate(self, request: ScenarioRequest) -> ScenarioPack:
        self.trace = {}
        initial_call_count = self.llm.call_count
        request_decision = self.safety_policy.evaluate_request(request)
        if not request_decision.passed:
            raise ValueError(
                "Request failed safety policy: " + "; ".join(request_decision.blocked_items)
            )

        runner = NodeRunner(llm=self.llm, retry_policy=self.retry_policy)
        if request.is_ad_hoc:
            return await self._generate_ad_hoc(
                request, runner, initial_call_count, request_decision
            )

        identity_out = ActorIdentityOutput.model_validate(
            (
                await runner.run(
                    "actor_identity",
                    {"actor": request.actor, "request": request.model_dump(mode="json")},
                )
            ).model_dump(mode="json")
        )

        local_attack = self._local_attack_context(request.actor)
        queries = identity_out.queries or [f"{request.actor} ATT&CK techniques"]
        source_candidates, search_errors = await self._search_sources(queries)
        extraction = await self.source_extractor.extract_many(source_candidates)
        source_documents, excluded_by_date = self._filter_recent_sources(
            extraction.documents, request
        )
        source_records = extraction.records

        retrieval_payload = {
            "actor": request.actor,
            "identity": identity_out.model_dump(mode="json"),
            "local_attack": local_attack,
            "source_documents": [document.model_context() for document in source_documents],
            "minimum_source_date": request.minimum_source_date.isoformat(),
        }

        attack_model, advisory_model, detection_model = await asyncio.gather(
            runner.run("attack_extraction", retrieval_payload),
            runner.run("advisory_extraction", retrieval_payload),
            runner.run("detection_extraction", retrieval_payload),
        )
        attack_out = AttackExtractionOutput.model_validate(attack_model.model_dump(mode="json"))
        advisory_out = AdvisoryExtractionOutput.model_validate(
            advisory_model.model_dump(mode="json")
        )
        detection_out = DetectionExtractionOutput.model_validate(
            detection_model.model_dump(mode="json")
        )

        graph_builder = CitationGraphBuilder(source_documents)
        graph_builder.add_claims("attack_extraction", attack_out.claims)
        graph_builder.add_claims("advisory_extraction", advisory_out.claims)
        graph_builder.add_claims("detection_extraction", detection_out.claims)
        early_graph = graph_builder.build()

        dossier_out = DossierSynthesisOutput.model_validate(
            (
                await runner.run(
                    "dossier_synthesis",
                    {
                        "request": request.model_dump(mode="json"),
                        "identity": identity_out.model_dump(mode="json"),
                        "attack": attack_out.model_dump(mode="json"),
                        "advisories": advisory_out.model_dump(mode="json"),
                        "detections": detection_out.model_dump(mode="json"),
                        "citation_graph": early_graph.model_dump(mode="json"),
                    },
                )
            ).model_dump(mode="json")
        )
        graph_builder.add_claims("dossier_synthesis", dossier_out.claims)

        shared = {
            "request": request.model_dump(mode="json"),
            "dossier": dossier_out.model_dump(mode="json"),
            "citation_graph": graph_builder.build().model_dump(mode="json"),
        }

        environment_model, roe_model, telemetry_model = await asyncio.gather(
            runner.run("environment_fit", shared),
            runner.run("roe_translation", shared),
            runner.run("telemetry_mapping", shared),
        )
        environment_out = EnvironmentFitOutput.model_validate(
            environment_model.model_dump(mode="json")
        )
        roe_out = RoeTranslationOutput.model_validate(roe_model.model_dump(mode="json"))
        telemetry_out = TelemetryMappingOutput.model_validate(
            telemetry_model.model_dump(mode="json")
        )

        path_payload = {
            **shared,
            "environment_fit": environment_out.model_dump(mode="json"),
            "roe_translation": roe_out.model_dump(mode="json"),
            "telemetry": telemetry_out.model_dump(mode="json"),
        }

        path_a_model, path_b_model = await asyncio.gather(
            runner.run("path_candidate_a", path_payload),
            runner.run("path_candidate_b", path_payload),
        )
        path_a = PathCandidateOutput.model_validate(path_a_model.model_dump(mode="json"))
        path_b = PathCandidateOutput.model_validate(path_b_model.model_dump(mode="json"))
        graph_builder.add_claims("path_candidate_a", path_a.claims)
        graph_builder.add_claims("path_candidate_b", path_b.claims)

        adjudicated = PathAdjudicationOutput.model_validate(
            (
                await runner.run(
                    "path_adjudication",
                    {
                        **path_payload,
                        "candidate_a": path_a.model_dump(mode="json"),
                        "candidate_b": path_b.model_dump(mode="json"),
                    },
                )
            ).model_dump(mode="json")
        )
        graph_builder.add_claims("path_adjudication", adjudicated.claims)

        final_out = FinalCompositionOutput.model_validate(
            (
                await runner.run(
                    "final_composition",
                    {
                        **path_payload,
                        "adjudicated_path": adjudicated.model_dump(mode="json"),
                        "citation_graph": graph_builder.build().model_dump(mode="json"),
                        "validated_sources": [
                            record.model_dump(mode="json")
                            for record in source_records
                            if record.validated
                        ],
                    },
                )
            ).model_dump(mode="json")
        )
        graph_builder.add_claims("final_composition", final_out.claims)
        citation_graph = graph_builder.build()

        identity = self._build_identity(identity_out, local_attack, request.actor)
        techniques = self._filter_recent_techniques(
            self._build_techniques(dossier_out, attack_out, local_attack), request
        )
        if self.require_grounded_dossier and not techniques:
            raise ValueError(
                "Grounding policy failed: no source-supported ATT&CK techniques were resolved"
            )
        source_records = self._attach_claim_ids(source_records, graph_builder.source_claims())
        dossier = TTPDossier(
            identity=identity,
            techniques=techniques,
            software=dossier_out.software or attack_out.software,
            campaigns=dossier_out.campaigns or attack_out.campaigns,
            excluded_techniques=dossier_out.excluded_techniques,
            caveats=dossier_out.caveats,
            source_manifest=source_records,
        )

        steps = final_out.attack_path[: request.max_attack_path_steps]
        if not steps:
            steps = self._safe_demo_steps(request)
        step_decision = self.safety_policy.evaluate_steps(request, steps)
        if not step_decision.passed:
            raise ValueError(
                "Generated scenario failed safety policy: " + "; ".join(step_decision.blocked_items)
            )

        factuality = self.factuality_evaluator.evaluate(
            graph=citation_graph,
            final_claims=final_out.claims,
            techniques=techniques,
            steps=steps,
            local_attack=local_attack,
        )
        if self.fail_on_factuality_error and not factuality.passed:
            raise ValueError(
                "Generated scenario failed factuality policy: "
                + "; ".join(factuality.unsupported_claims)
            )

        cited_urls = citation_graph.cited_source_urls()
        cited_records = [
            record for record in source_records if str(record.final_url or record.url) in cited_urls
        ]
        source_ok = all(record.validated for record in cited_records)
        invalid_unused = [
            str(record.url)
            for record in source_records
            if not record.validated and str(record.url) not in cited_urls
        ]
        warnings = request_decision.warnings + step_decision.warnings
        if excluded_by_date:
            warnings.append(
                f"{len(excluded_by_date)} validated source(s) were excluded by the minimum source date."
            )
        warnings.extend(f"Search error: {item}" for item in search_errors)
        if invalid_unused:
            warnings.append(
                f"{len(invalid_unused)} retrieved source candidate(s) failed validation and were excluded."
            )

        model_calls = self.llm.call_count - initial_call_count
        qa = QAResult(
            unsupported_claims=factuality.unsupported_claims,
            blocked_items=step_decision.blocked_items,
            warnings=warnings,
            source_validation_passed=source_ok,
            factuality_passed=factuality.passed,
            factuality_score=factuality.score,
            citation_coverage=factuality.citation_coverage,
            safety_gate_passed=step_decision.passed,
            model_call_count=model_calls,
            repair_call_count=runner.repair_call_count,
        )

        self.trace = {
            "nodes": runner.trace,
            "retrieval": {
                "queries": queries[:4],
                "search_errors": search_errors,
                "candidate_count": len(source_candidates),
                "validated_count": sum(1 for item in source_records if item.validated),
                "document_count": len(source_documents),
                "excluded_by_minimum_source_date": excluded_by_date,
                "local_attack": local_attack,
            },
            "citation_graph": citation_graph.model_dump(mode="json"),
            "factuality": factuality.model_dump(mode="json"),
        }

        return ScenarioPack(
            title=f"{identity.canonical_name} Safe Red Team Exercise",
            request=request,
            dossier=dossier,
            executive_summary=final_out.executive_summary,
            exercise_assumptions=final_out.assumptions,
            attack_path=steps,
            injects=final_out.injects or self._demo_injects(),
            metrics=final_out.metrics,
            source_manifest=source_records,
            citation_graph=citation_graph,
            factuality=factuality,
            qa=qa,
            trace=self.trace,
        )

    async def _generate_ad_hoc(
        self,
        request: ScenarioRequest,
        runner: NodeRunner,
        initial_call_count: int,
        request_decision: Any,
    ) -> ScenarioPack:
        """Generate a red team scenario from a free-form premise without TTP grounding."""
        identity = ActorIdentity(
            canonical_name=request.actor,
            attack_id=None,
            aliases=[],
            confidence="low",
            ambiguity_notes=[
                "Ad hoc scenario: threat actor identity and ATT&CK grounding were not requested."
            ],
        )
        dossier = TTPDossier(
            identity=identity,
            techniques=[],
            software=[],
            campaigns=[],
            excluded_techniques=[],
            caveats=[
                "Ad hoc scenario generated from the supplied premise, not a TTP dossier.",
                "ATT&CK technique IDs are intentionally omitted unless explicitly supplied.",
            ],
            source_manifest=[],
        )
        citation_graph = CitationGraph()
        shared = {
            "request": request.model_dump(mode="json"),
            "ad_hoc": True,
            "ad_hoc_scenario": request.ad_hoc_scenario,
            "dossier": dossier.model_dump(mode="json"),
            "citation_graph": citation_graph.model_dump(mode="json"),
        }

        environment_model, roe_model, telemetry_model = await asyncio.gather(
            runner.run("environment_fit", shared),
            runner.run("roe_translation", shared),
            runner.run("telemetry_mapping", shared),
        )
        environment_out = EnvironmentFitOutput.model_validate(
            environment_model.model_dump(mode="json")
        )
        roe_out = RoeTranslationOutput.model_validate(roe_model.model_dump(mode="json"))
        telemetry_out = TelemetryMappingOutput.model_validate(
            telemetry_model.model_dump(mode="json")
        )
        path_payload = {
            **shared,
            "environment_fit": environment_out.model_dump(mode="json"),
            "roe_translation": roe_out.model_dump(mode="json"),
            "telemetry": telemetry_out.model_dump(mode="json"),
        }
        path_a_model, path_b_model = await asyncio.gather(
            runner.run("path_candidate_a", path_payload),
            runner.run("path_candidate_b", path_payload),
        )
        path_a = PathCandidateOutput.model_validate(path_a_model.model_dump(mode="json"))
        path_b = PathCandidateOutput.model_validate(path_b_model.model_dump(mode="json"))
        adjudicated = PathAdjudicationOutput.model_validate(
            (
                await runner.run(
                    "path_adjudication",
                    {
                        **path_payload,
                        "candidate_a": path_a.model_dump(mode="json"),
                        "candidate_b": path_b.model_dump(mode="json"),
                    },
                )
            ).model_dump(mode="json")
        )
        final_out = FinalCompositionOutput.model_validate(
            (
                await runner.run(
                    "final_composition",
                    {
                        **path_payload,
                        "adjudicated_path": adjudicated.model_dump(mode="json"),
                        "citation_graph": citation_graph.model_dump(mode="json"),
                        "validated_sources": [],
                    },
                )
            ).model_dump(mode="json")
        )

        steps = final_out.attack_path[: request.max_attack_path_steps] or self._safe_demo_steps(
            request
        )
        step_decision = self.safety_policy.evaluate_steps(request, steps)
        if not step_decision.passed:
            raise ValueError(
                "Generated scenario failed safety policy: " + "; ".join(step_decision.blocked_items)
            )
        factuality = self.factuality_evaluator.evaluate(
            graph=citation_graph,
            final_claims=final_out.claims,
            techniques=[],
            steps=steps,
            local_attack={"available": False, "ad_hoc": True},
        )
        if self.fail_on_factuality_error and not factuality.passed:
            raise ValueError(
                "Generated scenario failed factuality policy: "
                + "; ".join(factuality.unsupported_claims)
            )
        warnings = request_decision.warnings + step_decision.warnings
        model_calls = self.llm.call_count - initial_call_count
        qa = QAResult(
            unsupported_claims=factuality.unsupported_claims,
            blocked_items=step_decision.blocked_items,
            warnings=warnings,
            source_validation_passed=True,
            factuality_passed=factuality.passed,
            factuality_score=factuality.score,
            citation_coverage=factuality.citation_coverage,
            safety_gate_passed=step_decision.passed,
            model_call_count=model_calls,
            repair_call_count=runner.repair_call_count,
        )
        self.trace = {
            "nodes": runner.trace,
            "retrieval": {
                "ad_hoc": True,
                "queries": [],
                "search_errors": [],
                "candidate_count": 0,
                "validated_count": 0,
                "document_count": 0,
                "local_attack": {"available": False, "ad_hoc": True},
            },
            "citation_graph": citation_graph.model_dump(mode="json"),
            "factuality": factuality.model_dump(mode="json"),
        }
        return ScenarioPack(
            title=f"{request.actor} Ad Hoc Red Team Exercise",
            request=request,
            dossier=dossier,
            executive_summary=final_out.executive_summary,
            exercise_assumptions=final_out.assumptions,
            attack_path=steps,
            injects=final_out.injects or self._demo_injects(),
            metrics=final_out.metrics,
            source_manifest=[],
            citation_graph=citation_graph,
            factuality=factuality,
            qa=qa,
            trace=self.trace,
        )

    @staticmethod
    def _build_identity(
        identity: ActorIdentityOutput,
        local_attack: dict[str, Any],
        fallback_name: str,
    ) -> ActorIdentity:
        group = local_attack.get("group", {}) if local_attack.get("resolved") else {}
        return ActorIdentity(
            canonical_name=group.get("name") or identity.canonical_name or fallback_name,
            attack_id=group.get("attack_id") or identity.attack_id,
            aliases=sorted(set(identity.aliases + list(group.get("aliases", [])))),
            confidence="high" if group else identity.confidence,
            ambiguity_notes=identity.ambiguity_notes,
        )

    @staticmethod
    def _build_techniques(
        dossier: DossierSynthesisOutput,
        attack: AttackExtractionOutput,
        local_attack: dict[str, Any],
    ) -> list[TechniqueEvidence]:
        parsed = dossier.techniques or attack.techniques
        if parsed or not local_attack.get("resolved"):
            return parsed
        output: list[TechniqueEvidence] = []
        for item in local_attack.get("uses", {}).get("techniques", []):
            if not item.get("external_id") or not item.get("name"):
                continue
            output.append(
                TechniqueEvidence(
                    technique_id=item["external_id"],
                    name=item["name"],
                    rationale=item.get("description")
                    or "Relationship found in the pinned ATT&CK STIX bundle.",
                    confidence="high",
                    observed_after_2020=None,
                    source_urls=[],
                )
            )
        return output

    @staticmethod
    def _attach_claim_ids(
        records: list[SourceRecord],
        claim_ids_by_url: dict[str, list[str]],
    ) -> list[SourceRecord]:
        updated: list[SourceRecord] = []
        for record in records:
            final_url = str(record.final_url or record.url)
            claim_ids = claim_ids_by_url.get(final_url, [])
            updated.append(record.model_copy(update={"supports_claims": claim_ids}))
        return updated

    @staticmethod
    def _safe_demo_steps(request: ScenarioRequest) -> list[ProcedureStep]:
        asset = (
            request.environment.designated_test_assets[0]
            if request.environment.designated_test_assets
            else None
        )
        common = {
            "designated_test_asset": asset,
            "required_approvals": request.roe.required_approvals,
            "stop_conditions": [
                "Unexpected production impact is observed",
                "Activity leaves the authorized asset boundary",
                "Exercise control issues a stop command",
            ],
            "cleanup": [
                "Remove test artifacts",
                "Revoke or reset exercise credentials",
                "Confirm the asset returned to its baseline state",
            ],
            "safety_classification": SafetyClassification.CONTROLLED_EMULATION,
            "source_urls": [],
        }
        return [
            ProcedureStep(
                sequence=1,
                phase="Initial Access Validation",
                objective="Validate an approved initial-access control without targeting real users.",
                technique_ids=[],
                action_summary=(
                    "Use a pre-created exercise identity or benign test artifact to validate the "
                    "control path."
                ),
                safe_equivalent=(
                    "Demonstrate access only to the designated test asset and synthetic content."
                ),
                prerequisites=[
                    "Exercise identity",
                    "Approved access path",
                    "Defender telemetry enabled",
                ],
                expected_observables=[
                    ExpectedObservable(
                        source="Identity provider",
                        observable="Authentication and conditional-access decision",
                        collection_requirement="Exercise account logs retained",
                    )
                ],
                evidence_to_capture=[
                    "Timestamp",
                    "Exercise account",
                    "Control decision",
                    "Relevant alert IDs",
                ],
                detection_opportunities=[
                    "Unusual exercise-account sign-in",
                    "Policy decision correlation",
                ],
                assumptions=["No real employee is targeted"],
                **common,
            ),
            ProcedureStep(
                sequence=2,
                phase="Execution / Access Validation",
                objective="Generate safe endpoint or service telemetry on the designated asset.",
                technique_ids=[],
                action_summary=(
                    "Perform an approved benign action that resembles the selected behavior at "
                    "the telemetry level."
                ),
                safe_equivalent="Use an inert marker or signed test utility rather than a payload.",
                prerequisites=["Test utility approved", "Endpoint logging enabled"],
                expected_observables=[
                    ExpectedObservable(
                        source="Endpoint telemetry",
                        observable=(
                            "Process, parent-child, file, and network events associated with the "
                            "test action"
                        ),
                    )
                ],
                evidence_to_capture=[
                    "Process tree",
                    "File hash",
                    "Network destination",
                    "Alert disposition",
                ],
                detection_opportunities=[
                    "Behavioral rule coverage",
                    "Parent-child anomaly detection",
                ],
                assumptions=["The selected behavior is mapped only after dossier grounding"],
                **common,
            ),
            ProcedureStep(
                sequence=3,
                phase="Objective Access",
                objective=(
                    "Prove access to a protected business objective without touching real sensitive data."
                ),
                technique_ids=[],
                action_summary=(
                    "Access a synthetic canary record placed in the approved exercise location."
                ),
                safe_equivalent=(
                    "Capture the canary identifier and access log; do not copy production data."
                ),
                prerequisites=["Synthetic canary record", "Read-only exercise permission"],
                expected_observables=[
                    ExpectedObservable(
                        source="Data or cloud audit log",
                        observable="Read access to the canary object",
                    )
                ],
                evidence_to_capture=[
                    "Canary identifier",
                    "Access event",
                    "Identity",
                    "Alert or case ID",
                ],
                detection_opportunities=[
                    "Sensitive-object access analytics",
                    "Identity-to-data correlation",
                ],
                assumptions=["Synthetic data accurately represents the protected workflow"],
                **common,
            ),
            ProcedureStep(
                sequence=4,
                phase="Safe Impact Simulation",
                objective="Validate impact detection and response without destructive execution.",
                technique_ids=[],
                action_summary="Create a reversible impact marker on the designated test asset.",
                safe_equivalent=(
                    "Write a harmless marker file or toggle an isolated test-only flag, then "
                    "restore baseline."
                ),
                prerequisites=["Rollback verified", "Exercise controller present"],
                expected_observables=[
                    ExpectedObservable(
                        source="Endpoint and change monitoring",
                        observable="Creation and removal of the approved impact marker",
                    )
                ],
                evidence_to_capture=[
                    "Marker creation",
                    "Alert timing",
                    "Containment decision",
                    "Rollback evidence",
                ],
                detection_opportunities=[
                    "Impact-stage alerting",
                    "Change-control correlation",
                ],
                assumptions=["No production process depends on the test marker"],
                **common,
            ),
        ]

    @staticmethod
    def _demo_injects() -> list[ExerciseInject]:
        return [
            ExerciseInject(
                time_offset="T+00:15",
                audience="SOC",
                inject=("An authentication anomaly associated with the exercise identity appears."),
                expected_response="Triage identity, source, device, and policy context.",
                success_measure=(
                    "Correctly classify the event and preserve evidence within the target time."
                ),
            ),
            ExerciseInject(
                time_offset="T+00:45",
                audience="Incident Response",
                inject=(
                    "Endpoint telemetry indicates a benign but suspicious test action on the "
                    "designated asset."
                ),
                expected_response=(
                    "Correlate endpoint and identity evidence and decide whether containment is warranted."
                ),
                success_measure=(
                    "Document a defensible containment decision with no impact to production."
                ),
            ),
            ExerciseInject(
                time_offset="T+01:30",
                audience="Exercise Control",
                inject=(
                    "The synthetic objective artifact is accessed and the impact marker is created."
                ),
                expected_response=(
                    "Validate objective detection, initiate cleanup, and capture lessons learned."
                ),
                success_measure=(
                    "All artifacts are removed and telemetry gaps are assigned owners."
                ),
            ),
        ]
