import pytest

from adversaryflow.ai import CampaignRequest, OfflinePlanner, validate_ai_draft
from adversaryflow.emulation import load_catalog
from adversaryflow.models import RulesOfEngagement


def test_offline_planner_creates_approval_bound_draft():
    abilities = load_catalog("content/abilities/catalog.json")
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "local-lab", "validate endpoint process visibility"), abilities)
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["local-lab"]})
    validate_ai_draft(draft, roe, abilities)
    assert draft.approval_required is True
    assert draft.ability_ids


def test_ai_draft_cannot_escape_scope():
    abilities = load_catalog("content/abilities/catalog.json")
    draft = OfflinePlanner().draft(CampaignRequest("APT29", "production", "test"), abilities)
    roe = RulesOfEngagement.from_mapping({"engagement_name": "x", "operator_name": "o", "approver_name": "a", "approved_targets": ["local-lab"]})
    with pytest.raises(ValueError, match="outside"):
        validate_ai_draft(draft, roe, abilities)
