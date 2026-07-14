from __future__ import annotations

from dataclasses import dataclass, field

from adversaryflow.models import (
    ExerciseMode,
    ProcedureStep,
    SafetyClassification,
    ScenarioRequest,
)


@dataclass(slots=True)
class SafetyDecision:
    passed: bool
    blocked_items: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class SafetyPolicy:
    """Deterministic final gate. Prompts are guidance; this policy is enforcement."""

    destructive_markers = {
        "encrypt production files",
        "wipe disk",
        "delete backups",
        "destroy data",
        "disable safety controls",
        "transfer funds",
        "execute live transaction",
        "exfiltrate real customer data",
    }

    def evaluate_request(self, request: ScenarioRequest) -> SafetyDecision:
        blocked: list[str] = []
        warnings: list[str] = []
        if request.mode != ExerciseMode.TABLETOP and not request.environment.designated_test_assets:
            blocked.append("Non-tabletop execution requires at least one designated test asset")
        if not request.roe.no_destructive_execution:
            warnings.append(
                "RoE does not explicitly prohibit destructive execution; AdversaryFlow still blocks it"
            )
        if not request.roe.no_real_funds_or_transactions:
            blocked.append("AdversaryFlow does not permit real funds or live transactions")
        return SafetyDecision(passed=not blocked, blocked_items=blocked, warnings=warnings)

    def evaluate_steps(
        self,
        request: ScenarioRequest,
        steps: list[ProcedureStep],
    ) -> SafetyDecision:
        blocked: list[str] = []
        warnings: list[str] = []
        authorized_assets = set(request.roe.authorized_assets)
        designated_assets = set(request.environment.designated_test_assets)

        for step in steps:
            label = f"Step {step.sequence} ({step.phase})"
            combined = f"{step.action_summary} {step.safe_equivalent}".casefold()
            if step.safety_classification == SafetyClassification.PROHIBITED:
                blocked.append(f"{label} is classified as prohibited")
            if any(marker in combined for marker in self.destructive_markers):
                blocked.append(f"{label} contains a blocked destructive or financial action")
            if request.mode != ExerciseMode.TABLETOP:
                if not step.designated_test_asset:
                    blocked.append(f"{label} has no designated test asset")
                elif step.designated_test_asset not in designated_assets:
                    blocked.append(f"{label} references a non-designated test asset")
                if authorized_assets and step.designated_test_asset not in authorized_assets:
                    blocked.append(f"{label} references an asset outside the RoE allowlist")
            if not step.safe_equivalent.strip():
                blocked.append(f"{label} has no safe equivalent")
            if not step.stop_conditions:
                warnings.append(f"{label} has no explicit stop conditions")
            if not step.cleanup:
                warnings.append(f"{label} has no cleanup procedure")

        return SafetyDecision(passed=not blocked, blocked_items=blocked, warnings=warnings)
