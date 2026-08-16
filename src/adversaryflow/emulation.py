"""Safe emulation contracts inspired by IDPT Emulation.

This module models reviewable abilities and scenarios. It intentionally does not
execute operator-supplied commands or provide a remote execution channel.
"""

import hashlib
import json
from importlib.resources import files
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .catalog import load_catalog_document


SAFE_NETWORK_SCOPES = {"none", "loopback"}


def default_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("catalog.json")))


def curated_windows_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("curated-windows.json")))


def curated_linux_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("curated-linux.json")))


def curated_macos_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("curated-macos.json")))


def idpt_windows_collection_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("idpt-windows-collection.json")))


@dataclass(frozen=True)
class TelemetryExpectation:
    category: str
    description: str
    required: bool = True


@dataclass(frozen=True)
class Ability:
    id: str
    version: str
    name: str
    technique_id: str
    platform: str
    fidelity: str
    simulation_action: str
    expected_telemetry: tuple[TelemetryExpectation, ...]
    network_scope: str = "none"
    writes_only_run_root: bool = True
    cleanup_action: str | None = None
    procedure_id: str | None = None
    source_refs: tuple[str, ...] = ()
    execution_action: str | None = None
    execution_timeout_seconds: int = 30
    lifecycle_status: str = "active"
    replacement_id: str | None = None
    deprecation_reason: str | None = None

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "Ability":
        technique = raw.get("technique", {})
        expected = raw.get("expected", {})
        safety = raw.get("safety", {})
        ability = cls(
            id=str(raw["id"]),
            version=str(raw["version"]),
            name=str(raw["name"]),
            technique_id=str(technique["id"]),
            platform=str(raw["platform"]),
            fidelity=str(raw.get("fidelity", "synthetic")),
            simulation_action=str(raw["simulation_action"]),
            expected_telemetry=tuple(TelemetryExpectation(**item) for item in expected.get("telemetry", [])),
            network_scope=str(safety.get("network_scope", "none")),
            writes_only_run_root=bool(safety.get("writes_only_run_root", False)),
            cleanup_action=raw.get("cleanup_action"),
            procedure_id=raw.get("procedure_id"),
            source_refs=tuple(str(item) for item in raw.get("source_refs", [])),
            execution_action=raw.get("execution", {}).get("action"),
            execution_timeout_seconds=int(raw.get("execution", {}).get("timeout_seconds", 30)),
            lifecycle_status=str(raw.get("lifecycle", {}).get("status", "active")),
            replacement_id=raw.get("lifecycle", {}).get("replacement_id"),
            deprecation_reason=raw.get("lifecycle", {}).get("reason"),
        )
        validate_ability(ability)
        return ability


def validate_ability(ability: Ability) -> None:
    if ability.network_scope not in SAFE_NETWORK_SCOPES:
        raise ValueError("ability network_scope must be 'none' or 'loopback'")
    if not ability.writes_only_run_root:
        raise ValueError("ability must declare writes_only_run_root: true")
    if not ability.expected_telemetry:
        raise ValueError("ability must declare expected telemetry")
    if ability.procedure_id is not None and not ability.procedure_id.startswith("procedure-"):
        raise ValueError("ability procedure_id must reference a registered procedure")
    if ability.execution_action is not None and not ability.execution_action.startswith(("windows-", "linux-", "macos-")):
        raise ValueError("ability execution action must reference a fixed platform action")
    if not 1 <= ability.execution_timeout_seconds <= 60:
        raise ValueError("ability execution timeout must be between 1 and 60 seconds")
    if ability.lifecycle_status != "active":
        raise ValueError(f"ability {ability.id} is {ability.lifecycle_status}; create a new reviewed draft")


def load_catalog(path: str | Path) -> tuple[Ability, ...]:
    raw, _ = load_catalog_document(path)
    return tuple(Ability.from_mapping(item) for item in raw.get("abilities", []))


def canonical_plan_hash(plan: dict[str, Any]) -> str:
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_emulation_plan(abilities: tuple[Ability, ...], target: str, actor: str) -> dict[str, Any]:
    steps = [asdict(ability) for ability in abilities]
    plan = {
        "format": "ADVERSARYFLOW-EMULATION-1",
        "actor": actor,
        "target": target,
        "mode": "dry-run",
        "execution_boundary": "simulation-only",
        "steps": steps,
    }
    plan["plan_sha256"] = canonical_plan_hash(plan)
    return plan
