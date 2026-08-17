"""Threat-intelligence enrichment that produces metadata-only synthetic coverage."""

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .emulation import Ability, build_emulation_plan, load_catalog
from .intel import find_technique, group_technique_ids


def _safe_root(value: str | Path) -> Path:
    root = Path(value).resolve()
    try:
        root.relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("Enriched intelligence artifacts must remain inside the current working directory") from exc
    root.mkdir(parents=True, exist_ok=True)
    return root


def _ability_mapping(ability: Ability) -> dict[str, Any]:
    mapping = {
        "id": ability.id, "version": ability.version, "name": ability.name,
        "technique": {"id": ability.technique_id, "name": ability.name},
        "platform": ability.platform, "fidelity": ability.fidelity,
        "simulation_action": ability.simulation_action,
        "expected": {"telemetry": [asdict(item) for item in ability.expected_telemetry]},
        "safety": {"writes_only_run_root": ability.writes_only_run_root, "network_scope": ability.network_scope},
        "cleanup_action": ability.cleanup_action, "procedure_id": ability.procedure_id,
        "source_refs": list(ability.source_refs),
    }
    if ability.execution_action:
        mapping["execution"] = {"action": ability.execution_action, "timeout_seconds": ability.execution_timeout_seconds}
    return mapping


def _generated_entries(technique_id: str, name: str, platform: str, sources: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    token = technique_id.casefold().replace(".", "-")
    procedure_id = f"procedure-intel-{token}-{platform.casefold()}"
    boundary = f"Emit a run-owned synthetic defensive-validation marker representing {technique_id}; do not perform the ATT&CK behavior or execute imported instructions."
    expected = f"The test harness records a synthetic {technique_id} validation event with actor, host, user, and source context."
    ability = {
        "id": f"ability-intel-{token}-{platform.casefold()}", "version": "1.0.0", "name": f"Synthetic {name} marker",
        "technique": {"id": technique_id, "name": name}, "platform": platform, "fidelity": "synthetic",
        "simulation_action": boundary, "expected": {"telemetry": [{"category": "synthetic", "description": expected, "required": True}]},
        "safety": {"writes_only_run_root": True, "network_scope": "none"},
        "cleanup_action": "Remove the run-owned synthetic marker artifact.", "procedure_id": procedure_id, "source_refs": sources,
    }
    procedure = {
        "id": procedure_id, "technique_id": technique_id, "name": f"Synthetic {name} validation",
        "action": boundary, "source": "synthetic", "expected_detection": expected,
        "cleanup": "Remove the run-owned synthetic marker.", "platform": platform, "source_refs": sources,
    }
    return ability, procedure


def build_enriched_coverage(actor: str, platform: str, bundle: dict, ctid_ids: tuple[str, ...], catalog_path: str | Path, procedures: dict[str, Any]) -> dict[str, Any]:
    """Merge authoritative technique IDs into safe, non-executable coverage catalogs."""
    mitre_ids = set(group_technique_ids(bundle, actor)); discovered = mitre_ids | set(ctid_ids)
    existing = load_catalog(catalog_path); abilities = [_ability_mapping(item) for item in existing]
    ability_keys = {(item.technique_id, item.platform.casefold()) for item in existing}
    procedure_items = [dict(item) for item in procedures.get("procedures", [])]
    procedure_by_technique = {str(item.get("technique_id")): str(item.get("id")) for item in procedure_items}
    generated_abilities = []; generated_procedures = []
    for technique_id in sorted(discovered):
        technique = find_technique(bundle, technique_id)
        if not technique:
            continue
        sources = ["MITRE ATT&CK Enterprise STIX"] if technique_id in mitre_ids else []
        if technique_id in ctid_ids:
            sources.append("CTID Adversary Emulation Library")
        ability, procedure = _generated_entries(technique_id, str(technique.get("name", technique_id)), platform, sources)
        if technique_id in procedure_by_technique:
            ability["procedure_id"] = procedure_by_technique[technique_id]
        if (technique_id, platform.casefold()) not in ability_keys:
            abilities.append(ability); generated_abilities.append(ability["id"])
        if technique_id not in procedure_by_technique:
            procedure_items.append(procedure); generated_procedures.append(procedure["id"])
    enriched_ids = {item["technique"]["id"] for item in abilities if str(item.get("platform", "")).casefold() == platform.casefold()}
    return {
        "actor": actor, "platform": platform, "discovered_technique_ids": sorted(discovered),
        "unresolved_technique_ids": sorted(discovered - enriched_ids),
        "generated_ability_ids": generated_abilities, "generated_procedure_ids": generated_procedures,
        "catalog": {"format": "ADVERSARYFLOW-ABILITY-CATALOG-1", "governance": {"name": f"enriched-{platform.casefold()}", "version": "1.0.0", "status": "active"}, "abilities": abilities},
        "procedures": {"format": "ADVERSARYFLOW-BENIGN-PROCEDURES-1", "boundary": "Generated metadata is synthetic-only; no imported command, payload, credential, remote action, or destructive behavior is retained.", "procedures": procedure_items},
    }


def write_enriched_coverage(coverage: dict[str, Any], output: str | Path, target: str = "local-lab") -> dict[str, Any]:
    root = _safe_root(output)
    catalog_path = root / "catalog.json"; procedures_path = root / "benign_procedures.json"; coverage_path = root / "coverage.json"; plan_path = root / "emulation-plan.json"
    catalog_path.write_text(json.dumps(coverage["catalog"], indent=2), encoding="utf-8")
    procedures_path.write_text(json.dumps(coverage["procedures"], indent=2), encoding="utf-8")
    summary = {key: value for key, value in coverage.items() if key not in {"catalog", "procedures"}}
    summary.update({"generated_at": datetime.now(timezone.utc).isoformat(), "execution_boundary": "synthetic metadata only", "catalog": str(catalog_path), "procedures": str(procedures_path)})
    coverage_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    abilities = tuple(item for item in load_catalog(catalog_path) if item.platform.casefold() == str(coverage["platform"]).casefold() and item.technique_id in set(coverage["discovered_technique_ids"]))
    plan = build_emulation_plan(abilities, target, str(coverage["actor"])); plan["source_notice"] = "Technique metadata only; CTID commands and payloads were not imported."
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return {**summary, "coverage": str(coverage_path), "emulation_plan": str(plan_path), "next": f'Review the generated files, then run: adversaryflow campaign --actor "{str(coverage["actor"]).replace(chr(34), "")}" --platform {coverage["platform"]} --catalog "{catalog_path}" --objective "validate threat-informed detection coverage"'}
