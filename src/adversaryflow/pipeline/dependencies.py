from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from adversaryflow.models import ScenarioRequest


class Dependency(str, Enum):
    ACTOR = "actor"
    GROUNDING = "grounding"
    OBJECTIVE = "objective"
    MODE = "mode"
    ENVIRONMENT = "environment"
    ASSET_SCOPE = "asset_scope"
    ROE = "roe"
    OUTPUT = "output"


@dataclass(frozen=True, slots=True)
class NodeSpec:
    name: str
    dependencies: frozenset[Dependency]
    upstream: frozenset[str] = frozenset()


NODE_SPECS: dict[str, NodeSpec] = {
    "actor_identity": NodeSpec(
        "actor_identity", frozenset({Dependency.ACTOR, Dependency.GROUNDING})
    ),
    "attack_extraction": NodeSpec(
        "attack_extraction",
        frozenset({Dependency.GROUNDING}),
        frozenset({"actor_identity"}),
    ),
    "advisory_extraction": NodeSpec(
        "advisory_extraction",
        frozenset({Dependency.GROUNDING}),
        frozenset({"actor_identity"}),
    ),
    "detection_extraction": NodeSpec(
        "detection_extraction",
        frozenset({Dependency.GROUNDING}),
        frozenset({"actor_identity"}),
    ),
    "dossier_synthesis": NodeSpec(
        "dossier_synthesis",
        frozenset({Dependency.GROUNDING}),
        frozenset({"attack_extraction", "advisory_extraction", "detection_extraction"}),
    ),
    "environment_fit": NodeSpec(
        "environment_fit",
        frozenset(
            {
                Dependency.OBJECTIVE,
                Dependency.MODE,
                Dependency.ENVIRONMENT,
                Dependency.ASSET_SCOPE,
            }
        ),
        frozenset({"dossier_synthesis"}),
    ),
    "roe_translation": NodeSpec(
        "roe_translation",
        frozenset({Dependency.OBJECTIVE, Dependency.MODE, Dependency.ASSET_SCOPE, Dependency.ROE}),
        frozenset({"dossier_synthesis"}),
    ),
    "telemetry_mapping": NodeSpec(
        "telemetry_mapping",
        frozenset(
            {
                Dependency.OBJECTIVE,
                Dependency.MODE,
                Dependency.ENVIRONMENT,
                Dependency.ASSET_SCOPE,
            }
        ),
        frozenset({"dossier_synthesis"}),
    ),
    "path_candidate_a": NodeSpec(
        "path_candidate_a",
        frozenset({Dependency.OBJECTIVE, Dependency.MODE, Dependency.OUTPUT}),
        frozenset({"environment_fit", "roe_translation", "telemetry_mapping"}),
    ),
    "path_candidate_b": NodeSpec(
        "path_candidate_b",
        frozenset({Dependency.OBJECTIVE, Dependency.MODE, Dependency.OUTPUT}),
        frozenset({"environment_fit", "roe_translation", "telemetry_mapping"}),
    ),
    "path_adjudication": NodeSpec(
        "path_adjudication",
        frozenset(),
        frozenset({"path_candidate_a", "path_candidate_b"}),
    ),
    "final_composition": NodeSpec(
        "final_composition",
        frozenset({Dependency.OUTPUT}),
        frozenset({"path_adjudication"}),
    ),
}


def dependency_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "nodes": {
            name: {
                "dependencies": sorted(item.value for item in spec.dependencies),
                "upstream": sorted(spec.upstream),
            }
            for name, spec in NODE_SPECS.items()
        },
    }


def dependency_values(request: ScenarioRequest) -> dict[Dependency, object]:
    environment = request.environment.model_dump(mode="json")
    asset_scope = environment.pop("designated_test_assets")
    return {
        Dependency.ACTOR: request.actor,
        Dependency.GROUNDING: {
            "scenario_kind": request.scenario_kind.value,
            "post_2020_tradecraft_only": request.post_2020_tradecraft_only,
            "minimum_source_date": request.minimum_source_date.isoformat(),
        },
        Dependency.OBJECTIVE: {
            "objective": request.objective,
            "ad_hoc_scenario": request.ad_hoc_scenario,
        },
        Dependency.MODE: request.mode.value,
        Dependency.ENVIRONMENT: environment,
        Dependency.ASSET_SCOPE: asset_scope,
        Dependency.ROE: request.roe.model_dump(mode="json"),
        Dependency.OUTPUT: {
            "max_attack_path_steps": request.max_attack_path_steps,
            "output_audience": request.output_audience,
        },
    }


def changed_dependencies(before: ScenarioRequest, after: ScenarioRequest) -> frozenset[Dependency]:
    old = dependency_values(before)
    new = dependency_values(after)
    return frozenset(item for item in Dependency if old[item] != new[item])


def invalidated_nodes(changed: frozenset[Dependency]) -> list[str]:
    invalid = {name for name, spec in NODE_SPECS.items() if spec.dependencies.intersection(changed)}
    expanded = True
    while expanded:
        expanded = False
        for name, spec in NODE_SPECS.items():
            if name not in invalid and spec.upstream.intersection(invalid):
                invalid.add(name)
                expanded = True
    return [name for name in NODE_SPECS if name in invalid]


def grounding_request(request: ScenarioRequest) -> dict[str, object]:
    return {
        "actor": request.actor,
        "scenario_kind": request.scenario_kind.value,
        "post_2020_tradecraft_only": request.post_2020_tradecraft_only,
        "minimum_source_date": request.minimum_source_date.isoformat(),
    }


def environment_request(request: ScenarioRequest) -> dict[str, object]:
    return {
        "objective": request.objective,
        "scenario_kind": request.scenario_kind.value,
        "ad_hoc_scenario": request.ad_hoc_scenario,
        "mode": request.mode.value,
        "environment": request.environment.model_dump(mode="json"),
    }


def roe_request(request: ScenarioRequest) -> dict[str, object]:
    return {
        "objective": request.objective,
        "scenario_kind": request.scenario_kind.value,
        "ad_hoc_scenario": request.ad_hoc_scenario,
        "mode": request.mode.value,
        "environment": {
            "designated_test_assets": request.environment.designated_test_assets,
        },
        "roe": request.roe.model_dump(mode="json"),
    }


def telemetry_request(request: ScenarioRequest) -> dict[str, object]:
    return environment_request(request)
