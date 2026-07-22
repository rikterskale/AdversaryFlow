from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from adversaryflow.storage.common import atomic_write_json, read_json

CURRENT_STORE_VERSION = 2
Migration = Callable[[Path], None]


def _migrate_v0_to_v1(root: Path) -> None:
    """Add explicit versions and lifecycle metadata to pre-versioned run manifests."""
    runs = root / "runs"
    if runs.exists():
        for manifest_path in runs.glob("*/manifest.json"):
            manifest = read_json(manifest_path)
            manifest.setdefault("schema_version", 1)
            manifest.setdefault("status", "completed")
            manifest.setdefault("artifacts", {})
            manifest.setdefault("cache", {"nodes": {}, "sources": {}})
            atomic_write_json(manifest_path, manifest)
    atomic_write_json(root / "store.json", {"schema_version": 1})


def _migrate_v1_to_v2(root: Path) -> None:
    """Add explicit root/adaptation lineage to every stored run."""
    runs = root / "runs"
    if runs.exists():
        for manifest_path in runs.glob("*/manifest.json"):
            manifest = read_json(manifest_path)
            manifest["schema_version"] = 2
            manifest.setdefault(
                "lineage",
                {
                    "relationship": "root",
                    "parent_run_id": None,
                },
            )
            atomic_write_json(manifest_path, manifest)
    atomic_write_json(root / "store.json", {"schema_version": 2})


MIGRATIONS: dict[int, Migration] = {0: _migrate_v0_to_v1, 1: _migrate_v1_to_v2}


def store_version(root: Path) -> int:
    metadata = root / "store.json"
    if not metadata.exists():
        return 0
    version = read_json(metadata).get("schema_version", 0)
    if not isinstance(version, int):
        raise ValueError("Store schema_version must be an integer")
    return version


def migrate_store(root: Path) -> list[str]:
    root.mkdir(parents=True, exist_ok=True)
    version = store_version(root)
    if version > CURRENT_STORE_VERSION:
        raise ValueError(
            f"Store version {version} is newer than supported version {CURRENT_STORE_VERSION}"
        )
    applied: list[str] = []
    while version < CURRENT_STORE_VERSION:
        migration = MIGRATIONS.get(version)
        if migration is None:
            raise ValueError(f"No migration registered for store version {version}")
        migration(root)
        applied.append(f"v{version}->v{version + 1}")
        version += 1
    return applied
