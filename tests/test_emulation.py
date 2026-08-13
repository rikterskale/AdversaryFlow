import json

import pytest

from adversaryflow.emulation import Ability, build_emulation_plan, canonical_plan_hash, load_catalog


def test_catalog_loads_safe_abilities():
    abilities = load_catalog("content/abilities/catalog.json")
    assert len(abilities) == 2
    assert {ability.network_scope for ability in abilities} == {"none", "loopback"}


def test_ability_rejects_external_network_scope():
    raw = {
        "id": "bad", "version": "1", "name": "bad", "technique": {"id": "T1000"},
        "platform": "linux", "simulation_action": "test",
        "expected": {"telemetry": [{"category": "process", "description": "test"}]},
        "safety": {"writes_only_run_root": True, "network_scope": "internet"},
    }
    with pytest.raises(ValueError):
        Ability.from_mapping(raw)


def test_plan_hash_is_deterministic():
    plan = build_emulation_plan(load_catalog("content/abilities/catalog.json"), "local-lab", "APT29")
    stored = plan.pop("plan_sha256")
    assert stored == canonical_plan_hash(plan)
    assert json.dumps(plan, sort_keys=True)

