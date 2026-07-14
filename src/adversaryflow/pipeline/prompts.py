from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

PROMPT_DIR = Path(__file__).resolve().parents[1] / "prompts"
SchemaT = TypeVar("SchemaT", bound=BaseModel)


@lru_cache(maxsize=1)
def shared_prompt() -> str:
    philosophy = (PROMPT_DIR / "philosophy.md").read_text(encoding="utf-8")
    constraints = (PROMPT_DIR / "operational_constraints.md").read_text(encoding="utf-8")
    return f"{philosophy}\n\n{constraints}"


def node_prompt(node_name: str, schema: type[SchemaT]) -> str:
    node_instructions = {
        "actor_identity": "Resolve the actor identity and produce precise allowlisted search queries.",
        "attack_extraction": (
            "Extract only ATT&CK-supported actor relationships. Every actor-specific factual "
            "claim must include source URLs and, when available, a short supporting excerpt."
        ),
        "advisory_extraction": (
            "Extract dated observations from authoritative advisories and first-party reports. "
            "Preserve claim-level citations and exclude unsupported observations."
        ),
        "detection_extraction": (
            "Extract current detection names, telemetry requirements, technique mappings, and "
            "claim-level source URLs."
        ),
        "dossier_synthesis": (
            "Build a claim-level cited dossier from the supplied evidence graph. Exclude or mark "
            "anything that lacks support."
        ),
        "environment_fit": "Map supported behaviors to the supplied environment without inventing access.",
        "roe_translation": "Translate literal adversary behavior into enforceable safe exercise equivalents.",
        "telemetry_mapping": "Map steps to expected telemetry, collection prerequisites, and evidence.",
        "path_candidate_a": (
            "Create a realistic candidate path optimized for observability and learning value. "
            "Use only dossier-supported techniques."
        ),
        "path_candidate_b": (
            "Create a materially different candidate path using only dossier-supported behavior."
        ),
        "path_adjudication": (
            "Select or merge candidates based on evidence, RoE, environment fit, and safety."
        ),
        "final_composition": (
            "Produce the final structured scenario. Include a claims array for every actor-specific "
            "statement retained in the final output so deterministic factuality evaluation can audit it."
        ),
    }
    schema_json = json.dumps(schema.model_json_schema(), ensure_ascii=False, separators=(",", ":"))
    return (
        f"{shared_prompt()}\n\n"
        f"Node task: {node_instructions[node_name]}\n"
        "Return one JSON object only. It must validate against this JSON Schema exactly. "
        "Do not add keys not present in the schema.\n"
        f"JSON Schema: {schema_json}"
    )
