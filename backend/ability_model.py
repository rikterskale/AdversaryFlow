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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
    normalized = {
        "technique_id": technique_id,
        "platform": platform,
        "executor": executor,
        "command_template": command_text,
        "requirements": sorted({str(item) for item in prerequisites}),
        "cleanup": str(command.get("cleanup", "")),
        "rollback": str(command.get("rollback", command.get("cleanup", ""))),
        "fidelity": fidelity,
        "safety_class": safety_class,
        "requires_admin": bool(command.get("requires_admin", False)),
        "requires_network": bool(command.get("requires_network", False)),
        "network_targets": sorted({str(item) for item in targets}),
        "side_effects": sorted({str(item) for item in side_effects}),
        "timeout_seconds": int(command.get("timeout_seconds", 60)),
        "content_source": "legacy_python_catalog",
        "review_status": "unassessed",
    }
    digest = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    ability_id = hashlib.sha256(f"{technique_id}\0{platform}\0{executor}\0{digest}".encode("utf-8")).hexdigest()[:24]
    return Ability(ability_id=ability_id, content_sha256=digest, **normalized)
