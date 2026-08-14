from pathlib import Path
from uuid import uuid4

import pytest
from adversaryflow.actor_profiles import get_profile, list_profiles, plan_profile, run_profile, save_profile


def test_actor_profile_selects_only_safe_fixtures_and_links_retests():
    root = Path("artifacts") / f"actor-profiles-{uuid4()}"
    saved = save_profile({"name": "scattered-spider", "actor": "Scattered Spider", "aliases": ["UNC3944"], "sources": ["internal exercise brief", "ATT&CK"], "technique_ids": ["T1078.004", "T1098.001"], "fixture_ids": ["fixture-suspicious-sign-in", "fixture-oauth-credential-added"]}, root)
    assert saved["boundary"].startswith("fixed benign")
    assert get_profile("scattered-spider", root)["actor"] == "Scattered Spider"
    assert list_profiles(root)[0]["name"] == "scattered-spider"
    plan = plan_profile("scattered-spider", root)
    assert [item["id"] for item in plan["coverage"]] == ["fixture-oauth-credential-added", "fixture-suspicious-sign-in"]
    first = run_profile("scattered-spider", root=root)
    assert len(first["fixtures"]["fixtures"]) == 2
    second = run_profile("scattered-spider", first["fixtures"]["run_id"], root)
    assert second["fixtures"]["run_id"] != first["fixtures"]["run_id"]
    assert "retest" in plan["phases"]


@pytest.mark.parametrize("data", [
    {"name": "Bad Name", "actor": "Actor", "aliases": ["Actor"], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": ["fixture-suspicious-sign-in"]},
    {"name": "safe-profile", "actor": "Actor", "aliases": [], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": ["fixture-suspicious-sign-in"]},
    {"name": "safe-profile", "actor": "Actor", "aliases": ["Actor"], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": ["unknown-fixture"]},
    {"name": "safe-profile", "actor": "", "aliases": ["Actor"], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": ["fixture-suspicious-sign-in"]},
    {"name": "safe-profile", "actor": "Actor", "aliases": ["Actor"], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": [], "procedure_ids": []},
    {"name": "safe-profile", "actor": "Actor", "aliases": ["Actor"], "sources": ["source"], "technique_ids": ["T1000"], "fixture_ids": [], "procedure_ids": ["unknown-procedure"]},
])
def test_actor_profiles_reject_invalid_or_non_fixture_input(data):
    with pytest.raises(ValueError):
        save_profile(data, Path("artifacts") / f"actor-profiles-invalid-{uuid4()}")


def test_actor_profile_can_run_selected_fixed_benign_procedure():
    root = Path("artifacts") / f"actor-procedures-{uuid4()}"
    save_profile({"name": "generic-actor", "actor": "Any Actor", "aliases": ["Actor"], "sources": ["exercise brief"], "technique_ids": ["T1005"], "fixture_ids": [], "procedure_ids": ["procedure-dummy-data-read"]}, root)
    run = run_profile("generic-actor", root=root)
    assert len(run["procedures"]["procedures"]) == 1


def test_actor_profiles_reject_unknown_profiles_and_external_roots():
    root = Path("artifacts") / f"actor-profiles-missing-{uuid4()}"
    with pytest.raises(ValueError, match="not found"):
        get_profile("missing", root)
    with pytest.raises(ValueError, match="inside the current working directory"):
        list_profiles(Path.cwd().parent)
