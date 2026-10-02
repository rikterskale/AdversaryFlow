"""Validate plan contracts using the published, locally installed schemas."""
from __future__ import annotations

import json
import sysconfig
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

SCHEMA_FILES = {
    "2.0": "adversaryflow-plan.schema.json",
    "3.0": "adversaryflow-plan-v3.schema.json",
}


def schema_directory() -> Path:
    source = Path(__file__).resolve().parent.parent / "schemas"
    if source.is_dir():
        return source
    return Path(sysconfig.get_path("data")) / "share" / "adversaryflow" / "schemas"


@lru_cache(maxsize=1)
def _validators() -> dict[str, Draft202012Validator]:
    directory = schema_directory()
    schemas = {
        name: json.loads((directory / name).read_text(encoding="utf-8"))
        for name in (*SCHEMA_FILES.values(), "adversaryflow-receipt.schema.json")
    }
    # A closed registry resolves every reference locally, including in an
    # installed wheel. Submitted data cannot trigger remote schema retrieval.
    registry: Registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    checker = FormatChecker(formats=["date-time", "uri"])
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    return {
        version: Draft202012Validator(schemas[name], registry=registry, format_checker=checker)
        for version, name in SCHEMA_FILES.items()
    }


def validate_plan_document(document: Any) -> None:
    """Reject violations of either supported plan schema, including formats."""
    if not isinstance(document, dict):
        raise ValueError("Plan must be a JSON object")
    version = document.get("schema_version")
    if not isinstance(version, str) or version not in SCHEMA_FILES:
        raise ValueError("Only AdversaryFlow schema 2.0 or 3.0 plans are supported")
    try:
        # Refuse NaN, infinity, non-JSON objects and recursive data before the
        # schema validator examines numeric constraints or nested arrays.
        json.dumps(document, allow_nan=False, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Plan must contain valid finite JSON values") from exc
    try:
        _validators()[version].validate(document)
    except ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "plan"
        # Do not echo instance values (commands and evidence can be sensitive).
        raise ValueError(f"{path} violates plan schema {version} ({exc.validator})") from exc
    stages = document["stages"]
    if sum(len(stage["techniques"]) for stage in stages) > 4000:
        raise ValueError("Plan exceeds the 4000-step execution-kit limit")
