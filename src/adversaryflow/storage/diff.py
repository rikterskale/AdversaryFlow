from __future__ import annotations

from typing import Any

from pydantic import Field

from adversaryflow.models import ScenarioPack, StrictModel
from adversaryflow.pipeline.dependencies import changed_dependencies, invalidated_nodes


class ValueChange(StrictModel):
    path: str
    before: Any = None
    after: Any = None


class RunDiff(StrictModel):
    before_run_id: str | None = None
    after_run_id: str | None = None
    changed_dependencies: list[str] = Field(default_factory=list)
    predicted_invalidated_nodes: list[str] = Field(default_factory=list)
    actual_reused_nodes: list[str] = Field(default_factory=list)
    actual_executed_nodes: list[str] = Field(default_factory=list)
    request_changes: list[ValueChange] = Field(default_factory=list)
    scenario_changes: list[ValueChange] = Field(default_factory=list)


def _changes(before: Any, after: Any, path: str = "") -> list[ValueChange]:
    if isinstance(before, dict) and isinstance(after, dict):
        output: list[ValueChange] = []
        for key in sorted(set(before) | set(after)):
            child = f"{path}.{key}" if path else str(key)
            if key not in before:
                output.append(ValueChange(path=child, after=after[key]))
            elif key not in after:
                output.append(ValueChange(path=child, before=before[key]))
            else:
                output.extend(_changes(before[key], after[key], child))
        return output
    if before != after:
        return [ValueChange(path=path, before=before, after=after)]
    return []


def _semantic_pack(pack: ScenarioPack) -> dict[str, Any]:
    return {
        "title": pack.title,
        "executive_summary": pack.executive_summary,
        "exercise_assumptions": pack.exercise_assumptions,
        "attack_path": [item.model_dump(mode="json") for item in pack.attack_path],
        "injects": [item.model_dump(mode="json") for item in pack.injects],
        "metrics": pack.metrics,
        "dossier": {
            "identity": pack.dossier.identity.model_dump(mode="json"),
            "techniques": [item.model_dump(mode="json") for item in pack.dossier.techniques],
            "software": pack.dossier.software,
            "campaigns": pack.dossier.campaigns,
            "caveats": pack.dossier.caveats,
        },
        "quality": {
            "safety_gate_passed": pack.qa.safety_gate_passed,
            "factuality_passed": pack.qa.factuality_passed,
            "factuality_score": pack.qa.factuality_score,
            "citation_coverage": pack.qa.citation_coverage,
            "warnings": pack.qa.warnings,
            "blocked_items": pack.qa.blocked_items,
        },
    }


def build_run_diff(
    before: ScenarioPack,
    after: ScenarioPack,
    *,
    before_run_id: str | None = None,
    after_run_id: str | None = None,
) -> RunDiff:
    changed = changed_dependencies(before.request, after.request)
    node_trace = after.trace.get("nodes", {})
    reused_statuses = {"hit", "inherited"}
    reused = [
        name
        for name, item in node_trace.items()
        if item.get("cache", {}).get("status") in reused_statuses
    ]
    executed = [
        name
        for name, item in node_trace.items()
        if item.get("cache", {}).get("status") not in reused_statuses
    ]
    return RunDiff(
        before_run_id=before_run_id,
        after_run_id=after_run_id,
        changed_dependencies=sorted(item.value for item in changed),
        predicted_invalidated_nodes=invalidated_nodes(changed),
        actual_reused_nodes=reused,
        actual_executed_nodes=executed,
        request_changes=_changes(
            before.request.model_dump(mode="json"), after.request.model_dump(mode="json")
        ),
        scenario_changes=_changes(_semantic_pack(before), _semantic_pack(after)),
    )
