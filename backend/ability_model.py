"""Canonical, format-neutral view of reviewed or legacy catalog abilities.

This adapter preserves the existing catalog as the source of truth while
giving future content packs and format exporters a stable internal shape.
Legacy code-backed entries are explicitly marked unassessed; catalog presence
is not treated as content review approval.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Tuple

from .catalog_execution import identify_command

FIDELITY_VALUES = {"direct", "bounded_synthetic", "lab_proxy"}
SAFETY_CLASSES = {"none", "low", "medium", "high"}


@dataclass(frozen=True)
class Ability:
    ability_id: str
    technique_id: str
    platform: str
    executor: str
    command_template: str
    requirements: Tuple[str, ...]
    cleanup: str
    rollback: str
    fidelity: str
    safety_class: str
    requires_admin: bool
    requires_network: bool
    network_targets: Tuple[str, ...]
    side_effects: Tuple[str, ...]
    timeout_seconds: int
    content_source: str
    review_status: str
    content_sha256: str
    command_id: str = ""
    environment: str = "endpoint"
    execution_role: str = "endpoint_test"
    required_tools: Tuple[str, ...] = ()
    required_credentials: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if not self.command_id:
            result.pop("command_id")
        return result


def catalog_ability(technique_id: str, command: Mapping[str, Any]) -> Ability:
    """Normalize a catalog command into the internal ability contract."""
    command_text = command.get("command")
    if not isinstance(command_text, str) or not command_text:
        raise ValueError("catalog ability needs a non-empty command")
    platform = str(command.get("platform", "")).strip().lower()
    if platform not in {"windows", "linux", "macos"}:
        raise ValueError("catalog ability has an unsupported platform")
    executor = str(command.get("interpreter") or ("cmd" if platform == "windows" else "bash"))
    if executor not in {"cmd", "powershell", "bash"}:
        raise ValueError("catalog ability has an unsupported executor")
    risk = str(command.get("risk", "medium")).lower()
    safety_class = risk if risk in SAFETY_CLASSES else "medium"
    fidelity = str(command.get("fidelity", "direct"))
    if fidelity not in FIDELITY_VALUES:
        fidelity = "direct"
    prerequisites = command.get("prerequisites", [])
    targets = command.get("network_targets", [])
    side_effects = command.get("side_effects", [])
    requirements = tuple(sorted({str(item) for item in prerequisites}))
    cleanup = str(command.get("cleanup", ""))
    rollback = str(command.get("rollback", command.get("cleanup", "")))
    requires_admin = bool(command.get("requires_admin", False))
    requires_network = bool(command.get("requires_network", False))
    network_targets = tuple(sorted({str(item) for item in targets}))
    side_effect_values = tuple(sorted({str(item) for item in side_effects}))
    timeout_seconds = int(command.get("timeout_seconds", 60))
    normalized: Dict[str, Any] = {
        "command_id": str(command.get("command_id") or identify_command(dict(command))["command_id"]),
        "environment": str(command.get("environment", "endpoint")),
        "execution_role": str(command.get("execution_role", "endpoint_test")),
        "required_tools": tuple(command.get("required_tools", [])),
        "required_credentials": tuple(command.get("required_credentials", [])),
        "technique_id": technique_id,
        "platform": platform,
        "executor": executor,
        "command_template": command_text,
        "requirements": requirements,
        "cleanup": cleanup,
        "rollback": rollback,
        "fidelity": fidelity,
        "safety_class": safety_class,
        "requires_admin": requires_admin,
        "requires_network": requires_network,
        "network_targets": network_targets,
        "side_effects": side_effect_values,
        "timeout_seconds": timeout_seconds,
        "content_source": "legacy_python_catalog",
        "review_status": "unassessed",
    }
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    ability_id = hashlib.sha256(f"{technique_id}\0{platform}\0{executor}\0{digest}".encode("utf-8")).hexdigest()[:24]
    return Ability(
        ability_id=ability_id,
        technique_id=technique_id,
        platform=platform,
        executor=executor,
        command_template=command_text,
        requirements=requirements,
        cleanup=cleanup,
        rollback=rollback,
        fidelity=fidelity,
        safety_class=safety_class,
        requires_admin=requires_admin,
        requires_network=requires_network,
        network_targets=network_targets,
        side_effects=side_effect_values,
        timeout_seconds=timeout_seconds,
        content_source="legacy_python_catalog",
        review_status="unassessed",
        content_sha256=digest,
        command_id=normalized["command_id"],
        environment=normalized["environment"],
        execution_role=normalized["execution_role"],
        required_tools=normalized["required_tools"],
        required_credentials=normalized["required_credentials"],
    )
