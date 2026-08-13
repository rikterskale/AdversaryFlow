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


SAFE_NETWORK_SCOPES = {"none", "loopback"}


def default_catalog_path() -> Path:
    return Path(str(files("adversaryflow.resources").joinpath("catalog.json")))


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


def load_catalog(path: str | Path) -> tuple[Ability, ...]:
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
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
