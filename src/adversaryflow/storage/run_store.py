from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from adversaryflow.models import ScenarioPack, ScenarioRequest
from adversaryflow.storage.common import (
    atomic_write_bytes,
    atomic_write_json,
    sha256_bytes,
    sha256_json,
    read_json,
)
from adversaryflow.storage.migrations import CURRENT_STORE_VERSION, migrate_store


class RunStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        migrate_store(root)

    @staticmethod
    def new_run_id(request: ScenarioRequest) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        request_key = sha256_json(request.model_dump(mode="json"))[:10]
        return f"{stamp}-{request_key}-{uuid4().hex[:8]}"

    def save(
        self,
        *,
        run_id: str,
        pack: ScenarioPack,
        report: str,
        report_suffix: str,
        provider: str,
        cache: dict[str, object],
    ) -> Path:
        runs_dir = self.root / "runs"
        runs_dir.mkdir(parents=True, exist_ok=True)
        run_dir = runs_dir / run_id
        if run_dir.exists():
            raise FileExistsError(f"Run {run_id} already exists")
        staging = runs_dir / f".{run_id}.{uuid4().hex}.tmp"
        staging.mkdir()
        artifacts = {
            "request.json": pack.request.model_dump(mode="json"),
            "scenario-pack.json": pack.model_dump(mode="json"),
            "trace.json": pack.trace,
        }
        artifact_manifest: dict[str, dict[str, object]] = {}
        try:
            for name, payload in artifacts.items():
                path = staging / name
                atomic_write_json(path, payload)
                artifact_manifest[name] = {
                    "sha256": sha256_bytes(path.read_bytes()),
                    "bytes": path.stat().st_size,
                }
            report_name = f"report{report_suffix}"
            report_path = staging / report_name
            atomic_write_bytes(report_path, report.encode("utf-8"))
            artifact_manifest[report_name] = {
                "sha256": sha256_bytes(report_path.read_bytes()),
                "bytes": report_path.stat().st_size,
            }
            manifest = {
                "schema_version": CURRENT_STORE_VERSION,
                "run_id": run_id,
                "status": "completed",
                "created_at": pack.generated_at.isoformat(),
                "actor": pack.request.actor,
                "scenario_kind": pack.request.scenario_kind.value,
                "request_sha256": sha256_json(pack.request.model_dump(mode="json")),
                "scenario_pack_sha256": sha256_json(pack.model_dump(mode="json")),
                "provider": provider,
                "cache": cache,
                "artifacts": artifact_manifest,
            }
            atomic_write_json(staging / "manifest.json", manifest)
            os.replace(staging, run_dir)
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return run_dir

    def list_runs(self) -> list[dict[str, Any]]:
        runs_dir = self.root / "runs"
        manifests: list[dict[str, Any]] = []
        if not runs_dir.exists():
            return manifests
        for path in runs_dir.glob("*/manifest.json"):
            try:
                manifests.append(read_json(path))
            except (OSError, ValueError):
                continue
        return sorted(manifests, key=lambda item: str(item.get("created_at", "")), reverse=True)

    def load_manifest(self, run_id: str) -> dict[str, Any]:
        manifest = read_json(self.root / "runs" / run_id / "manifest.json")
        if manifest.get("schema_version") != CURRENT_STORE_VERSION:
            raise ValueError(f"Run {run_id} has an unsupported manifest version")
        return manifest

    def load_pack(self, run_id: str) -> ScenarioPack:
        return ScenarioPack.model_validate(
            read_json(self.root / "runs" / run_id / "scenario-pack.json")
        )

    def verify(self, run_id: str) -> list[str]:
        manifest = self.load_manifest(run_id)
        run_dir = self.root / "runs" / run_id
        failures: list[str] = []
        for name, metadata in manifest.get("artifacts", {}).items():
            path = run_dir / name
            if not path.is_file():
                failures.append(f"missing artifact: {name}")
                continue
            actual = sha256_bytes(path.read_bytes())
            if actual != metadata.get("sha256"):
                failures.append(f"hash mismatch: {name}")
        return failures
