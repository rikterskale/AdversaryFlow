"""Reviewed, data-driven IDPT scenario registry."""

import json
from importlib.resources import files
from typing import Any


def registry() -> dict[str, Any]:
    value = json.loads(files("adversaryflow.resources").joinpath("idpt_scenarios.json").read_text(encoding="utf-8"))
    if value.get("format") != "ADVERSARYFLOW-IDPT-SCENARIOS-1" or not isinstance(value.get("scenarios"), list):
        raise ValueError("IDPT scenario registry format is invalid")
    return value


def scenarios() -> tuple[dict[str, Any], ...]:
    reviewed = []
    for item in registry()["scenarios"]:
        mapping = item.get("ability_mapping")
        if item.get("reviewed") is not True or not isinstance(mapping, dict) or not mapping:
            raise ValueError("Every registered IDPT scenario must be reviewed and declare an ability mapping")
        if len(mapping) != len(set(mapping.values())):
            raise ValueError("IDPT scenario ability mappings must be one-to-one")
        reviewed.append(item)
    return tuple(reviewed)


def resolve_scenario(ability_ids: set[str]) -> dict[str, Any]:
    matches = [item for item in scenarios() if set(item["ability_mapping"]) == ability_ids]
    if len(matches) != 1:
        raise ValueError("idpt-local requires one complete packaged reviewed IDPT scenario catalog")
    return matches[0]
