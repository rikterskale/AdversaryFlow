from .models import CampaignPlan, CampaignStep, RulesOfEngagement
from .safety import require_simulation_action, validate_target


def build_plan(roe: RulesOfEngagement, actor: str, target: str, technique: dict, source: str) -> CampaignPlan:
    validate_target(roe, target)
    require_simulation_action(roe, "simulation")
    technique_id = next((ref["external_id"] for ref in technique.get("external_references", []) if ref.get("external_id", "").startswith("T")), "unknown")
    name = technique.get("name", "Unnamed technique")
    step = CampaignStep(
        technique_id=technique_id,
        name=name,
        objective=f"Validate visibility for {name} without changing system state.",
        simulation_action=f"Emit a benign, pre-registered simulation event representing {technique_id}.",
        expected_telemetry=("endpoint process or test-harness event", "centralized log ingestion", "SIEM correlation or alert outcome"),
        validation_questions=("Did the expected event arrive within the target window?", "Was the event enriched with user, host, and technique context?", "Could an analyst distinguish this simulation from normal activity?"),
    )
    return CampaignPlan(actor=actor, target=target, source=source, steps=(step,))

