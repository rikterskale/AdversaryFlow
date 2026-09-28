"""Generate reviewed internal abilities as an Atomic Red Team content pack.

Unreviewed or out-of-scope catalog entries are reported in the manifest and
never emitted as Atomic tests. The adapter serializes files only; it does not
install, invoke, or run an Atomic executor.
"""
from __future__ import annotations

import io
import json
import uuid
import zipfile
from typing import Any, Dict, List, Mapping, Tuple

from . import ability_model, command_catalog, execution_kit


class AtomicAdapterError(ValueError):
    """The input plan cannot be converted to an Atomic content pack."""


def _yaml_scalar(value: str) -> str:
    # JSON double-quoted strings are a valid, safely escaped YAML scalar.
    return json.dumps(value, ensure_ascii=False)


def _atomic_yaml(technique_id: str, display_name: str, ability: ability_model.Ability) -> bytes:
    executor_name = {"cmd": "command_prompt", "powershell": "powershell", "bash": "bash"}[ability.executor]
    guid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adversaryflow:{ability.ability_id}"))
    description = (
        f"AdversaryFlow reviewed lab ability. Fidelity: {ability.fidelity}. "
        f"Safety class: {ability.safety_class}. Requirements: {', '.join(ability.requirements) or 'none specified'}. "
        f"Side effects: {', '.join(ability.side_effects) or 'none specified'}. "
        f"Content SHA-256: {ability.content_sha256}."
    )
    lines = [
        f"attack_technique: {technique_id}",
        f"display_name: {_yaml_scalar(display_name)}",
        "atomic_tests:",
        f"  - name: {_yaml_scalar('AdversaryFlow reviewed lab ability')}",
        f"    auto_generated_guid: {_yaml_scalar(guid)}",
        f"    description: {_yaml_scalar(description)}",
        "    supported_platforms:",
        f"      - {ability.platform}",
        "    executor:",
        f"      name: {executor_name}",
        f"      elevation_required: {'true' if ability.requires_admin else 'false'}",
        f"      command: {_yaml_scalar(ability.command_template)}",
    ]
    if ability.cleanup:
        lines.append(f"      cleanup_command: {_yaml_scalar(ability.cleanup)}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_atomic_pack(document: Mapping[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
    """Create a ZIP with Atomic YAML for reviewed abilities and a gap backlog."""
    try:
        plan = execution_kit.rebind_to_catalog(document)
        normalized = execution_kit.normalize_plan(plan, require_executable=False)
    except execution_kit.ExecutionKitError as exc:
        raise AtomicAdapterError(str(exc)) from exc

    platform = normalized.platform
    scope = plan.get("scope", {})
    procedures = plan.get("procedures", []) if isinstance(plan.get("procedures", []), list) else []
    procedures_by_technique: Dict[str, List[str]] = {}
    for item in procedures:
        if isinstance(item, dict) and isinstance(item.get("technique_id"), str):
            candidate_id = item.get("candidate_id")
            if isinstance(candidate_id, str):
                procedures_by_technique.setdefault(item["technique_id"], []).append(candidate_id)

    included: List[Dict[str, Any]] = []
    files: List[Tuple[str, bytes]] = []
    gaps: List[Dict[str, Any]] = []
    for step in normalized.steps:
        catalog = command_catalog.get_commands(step.technique_id, step.technique_name, [step.tactic])
        candidates = [item for item in catalog["commands"]
                      if isinstance(item, dict) and item.get("platform") == platform]
        if not candidates:
            gaps.append({
                "technique_id": step.technique_id, "platform": platform,
                "gap": "no_ability", "reason": "The selected catalog pack has no ability for this platform.",
                "ability_id": None, "procedure_candidate_ids": procedures_by_technique.get(step.technique_id, []),
                "owner": None, "status": "open",
            })
            continue

        command = candidates[0]
        ability = ability_model.catalog_ability(step.technique_id, command)
        procedure_ids = procedures_by_technique.get(step.technique_id, [])
        out_of_scope = (
            (ability.requires_admin and not scope.get("allow_admin", False))
            or (ability.requires_network and not scope.get("allow_network", False))
            or (ability.safety_class == "high" and not scope.get("allow_high_risk", False))
            or (scope.get("curated_only", False) and catalog["source"] == "fallback")
        )
        if out_of_scope:
            gaps.append({
                "technique_id": step.technique_id, "platform": platform,
                "gap": "out_of_scope", "reason": "The ability is excluded by the plan scope or its required permissions.",
                "ability_id": ability.ability_id, "procedure_candidate_ids": procedure_ids,
                "owner": None, "status": "open",
            })
        elif procedure_ids and (catalog["source"] == "fallback" or ability.fidelity == "lab_proxy"):
            gaps.append({
                "technique_id": step.technique_id, "platform": platform,
                "gap": "wrong_shape", "reason": "An ability exists, but it is a generic lab test rather than the accepted report procedure.",
                "ability_id": ability.ability_id, "procedure_candidate_ids": procedure_ids,
                "owner": None, "status": "open",
            })
        elif ability.review_status != "reviewed":
            gaps.append({
                "technique_id": step.technique_id, "platform": platform,
                "gap": "not_accepted", "reason": "The ability has not passed content review.",
                "ability_id": ability.ability_id, "procedure_candidate_ids": procedure_ids,
                "owner": None, "status": "open",
            })
        else:
            path = f"atomics/{step.technique_id}/{step.technique_id}.yaml"
            files.append((path, _atomic_yaml(step.technique_id, step.technique_name, ability)))
            included.append({
                "technique_id": step.technique_id, "platform": platform,
                "ability_id": ability.ability_id, "content_sha256": ability.content_sha256,
                "review_status": ability.review_status, "fidelity": ability.fidelity,
                "safety_class": ability.safety_class, "requires_admin": ability.requires_admin,
                "requires_network": ability.requires_network, "network_targets": list(ability.network_targets),
                "requirements": list(ability.requirements), "cleanup": ability.cleanup,
                "rollback": ability.rollback, "procedure_candidate_ids": procedure_ids,
            })

    manifest = {
        "schema_version": "1.0",
        "adapter": "atomic-red-team",
        "adapter_status": "ready" if included and not gaps else "draft",
        "plan_sha256": normalized.plan_sha256,
        "data_version": normalized.data_version,
        "actor_id": normalized.actor_id,
        "platform": platform,
        "procedure_evidence": procedures,
        "included": included,
        "gaps": gaps,
        "summary": {"included": len(included), "gaps": len(gaps)},
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, body in files:
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o644 << 16
            output.writestr(info, body)
        info = zipfile.ZipInfo("adversaryflow-atomic-manifest.json")
        info.external_attr = 0o644 << 16
        output.writestr(info, json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"))
    return archive.getvalue(), manifest


def add_backlog_records(archive: bytes, manifest: Dict[str, Any], records: List[Mapping[str, Any]]) -> bytes:
    """Bind persisted backlog IDs and current ownership/status into the ZIP manifest."""
    indexed = {
        (item.get("technique_id"), item.get("platform"), item.get("gap"), item.get("ability_id"),
         tuple(item.get("procedure_candidate_ids", []))): item
        for item in records
    }
    for gap in manifest["gaps"]:
        record = indexed.get((gap.get("technique_id"), gap.get("platform"), gap.get("gap"), gap.get("ability_id"),
                              tuple(sorted(gap.get("procedure_candidate_ids", [])))))
        if record:
            gap["backlog_id"] = record["id"]
            gap["owner"] = record["owner"]
            gap["status"] = record["status"]
    files = []
    with zipfile.ZipFile(io.BytesIO(archive), "r") as current:
        for name in current.namelist():
            if name != "adversaryflow-atomic-manifest.json":
                files.append((name, current.read(name)))
    output_buffer = io.BytesIO()
    with zipfile.ZipFile(output_buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for name, body in files:
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o644 << 16
            output.writestr(info, body)
        info = zipfile.ZipInfo("adversaryflow-atomic-manifest.json")
        info.external_attr = 0o644 << 16
        output.writestr(info, json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8"))
    return output_buffer.getvalue()
