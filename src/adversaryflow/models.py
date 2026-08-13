from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class RulesOfEngagement:
    engagement_name: str
    operator_name: str
    approver_name: str
    approved_targets: tuple[str, ...]
    excluded_targets: tuple[str, ...] = ()
    environment: str = "local-lab"
    dry_run: bool = True
    allowed_actions: tuple[str, ...] = ("telemetry_validation", "simulation")

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RulesOfEngagement":
        required = ("engagement_name", "operator_name", "approver_name", "approved_targets")
        missing = [key for key in required if not data.get(key)]
        if missing:
            raise ValueError(f"RoE missing required fields: {', '.join(missing)}")
        if not data.get("dry_run", True):
            raise ValueError("MVP RoE must set dry_run: true")
        return cls(
            engagement_name=str(data["engagement_name"]),
            operator_name=str(data["operator_name"]),
            approver_name=str(data["approver_name"]),
            approved_targets=tuple(map(str, data["approved_targets"])),
            excluded_targets=tuple(map(str, data.get("excluded_targets", []))),
            environment=str(data.get("environment", "local-lab")),
            dry_run=True,
            allowed_actions=tuple(map(str, data.get("allowed_actions", ["telemetry_validation", "simulation"]))),
        )

    def allows(self, target: str) -> bool:
        return target in self.approved_targets and target not in self.excluded_targets


@dataclass(frozen=True)
class CampaignStep:
    technique_id: str
    name: str
    objective: str
    simulation_action: str
    expected_telemetry: tuple[str, ...]
    validation_questions: tuple[str, ...]
    risk_level: str = "Low"


@dataclass(frozen=True)
class CampaignPlan:
    actor: str
    target: str
    source: str
    steps: tuple[CampaignStep, ...]
    dry_run: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

