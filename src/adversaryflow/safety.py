from .models import RulesOfEngagement


class ScopeViolation(Exception):
    """Raised when a requested simulation target is outside the approved RoE."""


def validate_target(roe: RulesOfEngagement, target: str) -> None:
    if not roe.allows(target):
        raise ScopeViolation(
            f"Target '{target}' falls outside the authorized scope defined in the RoE."
        )


def require_simulation_action(roe: RulesOfEngagement, action: str) -> None:
    if action not in roe.allowed_actions:
        raise PermissionError(f"Action '{action}' is not approved by the RoE.")

