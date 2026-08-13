import pytest

from adversaryflow.models import RulesOfEngagement
from adversaryflow.safety import ScopeViolation, validate_target
from adversaryflow.ai import SAFE_ASSISTANT_INSTRUCTIONS


def test_roe_requires_dry_run():
    with pytest.raises(ValueError):
        RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["lab"], "dry_run": False})


def test_scope_rejects_target_outside_allowlist():
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["lab"]})
    with pytest.raises(ScopeViolation):
        validate_target(roe, "production")


def test_scope_accepts_allowlisted_target():
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["lab"]})
    validate_target(roe, "lab")


def test_ai_instructions_keep_assistant_defensive():
    assert "Do not provide exploit payloads" in SAFE_ASSISTANT_INSTRUCTIONS
