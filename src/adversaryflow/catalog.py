"""Governance and integrity checks for versioned ability catalogs."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any


CATALOG_FORMAT = "ADVERSARYFLOW-ABILITY-CATALOG-1"
CATALOG_MANIFEST_FORMAT = "ADVERSARYFLOW-CATALOG-MANIFEST-1"
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_STATUSES = {"active", "deprecated", "retired"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def catalog_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_catalog_document(raw: dict[str, Any], source: str | Path = "catalog", require_governance: bool = False) -> dict[str, Any]:
    if raw.get("format") != CATALOG_FORMAT:
        raise ValueError(f"{source} must use {CATALOG_FORMAT}")
    abilities = raw.get("abilities")
    if not isinstance(abilities, list) or not abilities:
        raise ValueError(f"{source} must contain a non-empty abilities list")
    governance = raw.get("governance")
    if require_governance and not isinstance(governance, dict):
        raise ValueError(f"{source} is missing catalog governance metadata")
    if governance is None:
        governance = {"name": Path(source).stem, "version": "0.0.0", "status": "active"}
    name = governance.get("name")
    version = governance.get("version")
    status = governance.get("status")
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{source} governance.name must be a non-empty string")
    if not isinstance(version, str) or not _SEMVER.fullmatch(version):
        raise ValueError(f"{source} governance.version must use semantic versioning")
    if status not in _STATUSES:
        raise ValueError(f"{source} governance.status must be active, deprecated, or retired")
    if status != "active":
        raise ValueError(f"{source} catalog is {status}; create a new reviewed draft from an active catalog")
    ids: set[str] = set()
    for item in abilities:
        if not isinstance(item, dict):
            raise ValueError(f"{source} contains a non-object ability")
        ability_id = item.get("id")
        if not isinstance(ability_id, str) or not ability_id:
            raise ValueError(f"{source} ability IDs must be non-empty strings")
        if ability_id in ids:
            raise ValueError(f"{source} contains duplicate ability ID: {ability_id}")
        ids.add(ability_id)
        lifecycle = item.get("lifecycle", {"status": "active"})
        if not isinstance(lifecycle, dict) or lifecycle.get("status", "active") not in _STATUSES:
            raise ValueError(f"{source} ability {ability_id} has invalid lifecycle status")
        if lifecycle.get("status", "active") != "active":
            raise ValueError(f"{source} ability {ability_id} is deprecated or retired; create a new reviewed draft")
    return governance


def load_catalog_document(path: str | Path, require_governance: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    source = Path(path)
    with source.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    governance = validate_catalog_document(raw, source, require_governance=require_governance)
    return raw, governance


def catalog_release_record(path: str | Path) -> dict[str, Any]:
    raw, governance = load_catalog_document(path, require_governance=True)
    return {
        "name": governance["name"],
        "version": governance["version"],
        "status": governance["status"],
        "path": Path(path).as_posix(),
        "sha256": catalog_sha256(path),
        "ability_ids": [item["id"] for item in raw["abilities"]],
    }
