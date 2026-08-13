import json
from dataclasses import dataclass
from typing import Any, Protocol

from .emulation import Ability
from .models import CampaignPlan, RulesOfEngagement


SAFE_ASSISTANT_INSTRUCTIONS = """You are AdversaryFlow's purple-team planning assistant.
Only support authorized defensive validation in the approved lab or engagement scope.
Do not provide exploit payloads, credential theft, persistence, evasion, destructive actions,
or instructions for targeting systems outside the supplied RoE. Prefer benign simulations,
telemetry checks, rollback steps, and analyst validation questions. Label assumptions and
identify missing approvals before proposing a plan.
"""


def build_review_prompt(plan: CampaignPlan) -> str:
    """Create a provider-neutral prompt for an AI review/drafting service."""
    steps = "\n".join(
        f"- {step.technique_id} ({step.name}): {step.simulation_action}"
        for step in plan.steps
    )
    return (
        f"{SAFE_ASSISTANT_INSTRUCTIONS}\n\n"
        f"Engagement actor profile: {plan.actor}\n"
        f"Approved simulation target: {plan.target}\n"
        f"Source: {plan.source}\n"
        f"Mode: {'DRY RUN' if plan.dry_run else 'REVIEW REQUIRED'}\n\n"
        "Review the following defensive campaign steps. Return: prerequisites, manager approval "
        "questions, expected telemetry, logging gaps to check, rollback/stop conditions, and a "
        "novice-friendly validation checklist. Do not add executable offensive commands.\n"
        f"{steps}"
    )


@dataclass(frozen=True)
class CampaignRequest:
    actor: str
    target: str
    objective: str
    platform: str = "linux"


@dataclass(frozen=True)
class AICampaignDraft:
    actor: str
    target: str
    objective: str
    ability_ids: tuple[str, ...]
    risk_level: str
    approval_required: bool
    expected_telemetry: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    assumptions: tuple[str, ...]
    source_refs: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {"actor": self.actor, "target": self.target, "objective": self.objective,
                "ability_ids": list(self.ability_ids), "risk_level": self.risk_level,
                "approval_required": self.approval_required,
                "expected_telemetry": list(self.expected_telemetry),
                "stop_conditions": list(self.stop_conditions), "assumptions": list(self.assumptions),
                "source_refs": list(self.source_refs)}


class AIPlanner(Protocol):
    def draft(self, request: CampaignRequest, abilities: tuple[Ability, ...]) -> AICampaignDraft: ...


class OfflinePlanner:
    """Deterministic fallback used when no model provider is configured."""

    def draft(self, request: CampaignRequest, abilities: tuple[Ability, ...]) -> AICampaignDraft:
        selected = tuple(a for a in abilities if a.platform == request.platform)
        return AICampaignDraft(
            actor=request.actor, target=request.target, objective=request.objective,
            ability_ids=tuple(a.id for a in selected), risk_level="Low", approval_required=True,
            expected_telemetry=tuple(t.description for a in selected for t in a.expected_telemetry),
            stop_conditions=("Target leaves the approved RoE.", "Operator invokes the kill switch.", "Unexpected non-loopback network activity is requested."),
            assumptions=("All selected abilities are synthetic or behavioral simulations.", "No arbitrary command strings are accepted."),
        )


def validate_ai_draft(draft: AICampaignDraft, roe: RulesOfEngagement, abilities: tuple[Ability, ...]) -> None:
    """Fail closed on model output before it can become an emulation plan."""
    if not roe.allows(draft.target):
        raise ValueError("AI draft target is outside the approved RoE")
    unknown = set(draft.ability_ids) - {a.id for a in abilities}
    if unknown:
        raise ValueError(f"AI draft selected unknown abilities: {', '.join(sorted(unknown))}")
    if not draft.approval_required:
        raise ValueError("AI drafts must require human approval")
    if draft.risk_level not in {"Low", "Medium", "High"}:
        raise ValueError("AI draft risk_level is invalid")


def build_ai_request_prompt(request: CampaignRequest, abilities: tuple[Ability, ...]) -> str:
    catalog = json.dumps([{"id": a.id, "name": a.name, "technique_id": a.technique_id,
                           "platform": a.platform, "network_scope": a.network_scope} for a in abilities], sort_keys=True)
    return (f"{SAFE_ASSISTANT_INSTRUCTIONS}\nReturn JSON only matching AICampaignDraft. "
            "Select only ability IDs from this catalog. Always set approval_required to true. "
            "Never add commands or new abilities.\n\n"
            f"Request: {json.dumps(request.__dict__, sort_keys=True)}\nAbility catalog: {catalog}")  # nosec B608
