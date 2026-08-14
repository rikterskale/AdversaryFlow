"""Defensive detection-as-code validation mappings for reviewed abilities."""

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from .emulation import Ability


def registry() -> dict[str, Any]:
    return json.loads(files("adversaryflow.resources").joinpath("detection_mappings.json").read_text(encoding="utf-8"))


def mappings(abilities: tuple[Ability, ...], technique_id: str = "") -> list[dict[str, Any]]:
    chosen = technique_id.strip().upper()
    overrides = registry().get("techniques", {})
    result = []
    for ability in abilities:
        if chosen and ability.technique_id != chosen and not ability.technique_id.startswith(chosen + "."):
            continue
        configured = overrides.get(ability.technique_id, {})
        result.append({
            "ability_id": ability.id,
            "ability": ability.name,
            "technique_id": ability.technique_id,
            "telemetry": [item.description for item in ability.expected_telemetry],
            "vendor_rule_ids": configured.get("vendor_rule_ids", {}),
            "templates": {
                "sigma": {"title": f"AdversaryFlow {ability.technique_id} validation marker", "logsource": {"category": ability.expected_telemetry[0].category}, "detection": {"selection": {"adversaryflow.ability_id": ability.id, "adversaryflow.run_id": "{run_id}"}, "condition": "selection"}},
                "sentinel_kql": f'AdversaryFlow_CL | where run_id_s == "{{run_id}}" and ability_id_s == "{ability.id}"',
                "splunk_spl": f'index=* adversaryflow_run_id="{{run_id}}" adversaryflow_ability_id="{ability.id}"',
                "elastic_eql": f'any where adversaryflow.run_id == "{{run_id}}" and adversaryflow.ability_id == "{ability.id}"',
            },
            "review": "Replace placeholders and map fields to the organization-owned schema before enabling a rule.",
        })
    return result


def write_bundle(abilities: tuple[Ability, ...], output: str | Path) -> dict[str, Any]:
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "ADVERSARYFLOW-DETECTION-MAPPINGS-1",
        "boundary": "Defensive validation templates only; no rule is deployed or vendor API queried.",
        "mappings": mappings(abilities),
    }
    path = root / "detection-mappings.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"mapping_count": len(payload["mappings"]), "bundle": str(path), "boundary": payload["boundary"]}
