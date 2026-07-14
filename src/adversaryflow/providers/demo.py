from __future__ import annotations

from typing import Any


class DemoLLMProvider:
    """Deterministic provider used to exercise the DAG without external calls."""

    def __init__(self) -> None:
        self.call_count = 0

    async def complete_json(
        self,
        *,
        call_name: str,
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> dict[str, Any]:
        self.call_count += 1
        actor = user_payload.get("actor") or user_payload.get("request", {}).get("actor", "Actor")
        request = user_payload.get("request", {})
        environment = request.get("environment", {})
        roe = request.get("roe", {})

        candidate_a = [
            {
                "phase": "Initial Access Validation",
                "objective": "Validate an approved access-control path.",
                "technique_ids": [],
                "action_summary": "Use a pre-created exercise identity.",
                "safe_equivalent": "Target only the designated test asset and synthetic content.",
                "rationale": "Maximizes defender-visible identity evidence.",
                "source_urls": [],
            }
        ]
        candidate_b = [
            {
                "phase": "Identity Boundary Validation",
                "objective": "Validate authorization boundaries with an exercise account.",
                "technique_ids": [],
                "action_summary": "Attempt an approved access path using test credentials.",
                "safe_equivalent": "Do not collect or reuse real credentials.",
                "rationale": "Provides a materially different identity-led path.",
                "source_urls": [],
            }
        ]

        responses: dict[str, dict[str, Any]] = {
            "actor_identity": {
                "canonical_name": actor,
                "attack_id": None,
                "aliases": [],
                "confidence": "low",
                "ambiguity_notes": ["Demo mode does not perform live identity resolution."],
                "queries": [f"{actor} ATT&CK techniques", f"{actor} detection guidance"],
            },
            "attack_extraction": {
                "techniques": [],
                "software": [],
                "campaigns": [],
                "claims": [],
            },
            "advisory_extraction": {"observations": [], "claims": []},
            "detection_extraction": {"detections": [], "claims": []},
            "dossier_synthesis": {
                "techniques": [],
                "software": [],
                "campaigns": [],
                "excluded_techniques": [],
                "caveats": [
                    "Demo mode intentionally omits live-grounded actor claims.",
                    "Connect a local ATT&CK bundle and Brave search for production use.",
                ],
                "claims": [],
            },
            "environment_fit": {
                "applicable_surfaces": environment.get("platforms", []),
                "excluded_surfaces": [],
                "feasible_technique_ids": [],
                "assumptions": ["The exercise uses only designated test assets."],
            },
            "roe_translation": {
                "mandatory_controls": [
                    "No destructive execution",
                    "No real funds or live transactions",
                    "Phishing only against explicitly authorized recipients",
                    "Use safe equivalents when literal behavior conflicts with RoE",
                ],
                "prohibited_actions": roe.get("prohibited_actions", []),
                "safe_equivalents": ["Use synthetic data and reversible test artifacts."],
                "approval_requirements": roe.get("required_approvals", []),
            },
            "telemetry_mapping": {
                "telemetry": [
                    "Identity authentication logs",
                    "Endpoint process and network telemetry",
                    "DNS and proxy logs",
                    "Cloud control-plane audit logs where applicable",
                ],
                "collection_gaps": [],
                "evidence_requirements": ["Preserve timestamps, alert IDs, and test identities."],
            },
            "path_candidate_a": {
                "name": "observable-first validation path",
                "strategy": "Prioritize telemetry-rich, reversible actions.",
                "steps": candidate_a,
                "tradeoffs": ["Demo mode does not map actor-specific techniques."],
                "claims": [],
            },
            "path_candidate_b": {
                "name": "identity-led validation path",
                "strategy": "Prioritize authorization and identity-control testing.",
                "steps": candidate_b,
                "tradeoffs": ["Demo mode does not map actor-specific techniques."],
                "claims": [],
            },
            "path_adjudication": {
                "selected": "observable-first validation path",
                "rationale": (
                    "It maximizes defender-visible evidence while remaining inside the supplied RoE."
                ),
                "sequence": candidate_a,
                "rejected_elements": [],
                "claims": [],
            },
            "final_composition": {
                "executive_summary": (
                    f"This is a safe, threat-informed exercise shell for {actor}. "
                    "Demo mode validates orchestration and policy controls but does not assert "
                    "live actor TTPs."
                ),
                "assumptions": [
                    "All actions occur in the approved exercise window.",
                    "Only designated test assets and exercise identities are used.",
                    "Synthetic data replaces production-sensitive data.",
                ],
                "metrics": [
                    "Time to first high-confidence alert",
                    "Percentage of expected telemetry observed",
                    "Analyst time to correctly map activity to ATT&CK",
                    "Containment decision quality",
                    "Cleanup completion and evidence integrity",
                ],
                "attack_path": [],
                "injects": [],
                "claims": [],
            },
        }
        return responses.get(call_name, {})
