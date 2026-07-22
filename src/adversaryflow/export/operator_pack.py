from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from adversaryflow.models import ScenarioPack
from adversaryflow.render import render_html
from adversaryflow.storage.common import atomic_write_bytes, sha256_bytes


def _bullets(items: list[str], empty: str = "None recorded.") -> str:
    return "\n".join(f"- {item}" for item in items) if items else empty


def operator_files(pack: ScenarioPack, *, run_id: str) -> dict[str, bytes]:
    summary = f"""# Executive Summary

**Run ID:** `{run_id}`
**Scenario:** {pack.title}
**Mode:** {pack.request.mode.value}
**Safety gate:** {"PASS" if pack.qa.safety_gate_passed else "FAIL"}

{pack.executive_summary}

## Exercise objective

{pack.request.objective}

## Required approvals

{_bullets(pack.request.roe.required_approvals)}
"""
    inject_lines = ["# Operator Injects", ""]
    for index, inject in enumerate(pack.injects, 1):
        inject_lines.extend(
            [
                f"## {index}. {inject.time_offset} — {inject.audience}",
                "",
                inject.inject,
                "",
                f"**Expected response:** {inject.expected_response}",
                "",
                f"**Success measure:** {inject.success_measure}",
                "",
            ]
        )

    action_lines = ["# Authorized Safe Actions", ""]
    for step in pack.attack_path:
        action_lines.extend(
            [
                f"## {step.sequence}. {step.phase}",
                "",
                f"- **Objective:** {step.objective}",
                f"- **Action summary:** {step.action_summary}",
                f"- **Safe equivalent:** {step.safe_equivalent}",
                f"- **Test asset:** {step.designated_test_asset or 'Tabletop only'}",
                f"- **Required approvals:** {', '.join(step.required_approvals) or 'None listed'}",
                f"- **Classification:** {step.safety_classification.value}",
                "",
            ]
        )

    telemetry_lines = ["# Expected Telemetry", ""]
    for step in pack.attack_path:
        telemetry_lines.extend([f"## {step.sequence}. {step.phase}", ""])
        for observable in step.expected_observables:
            requirement = (
                f" — collection requirement: {observable.collection_requirement}"
                if observable.collection_requirement
                else ""
            )
            telemetry_lines.append(
                f"- **{observable.source}:** {observable.observable}{requirement}"
            )
        if not step.expected_observables:
            telemetry_lines.append("- No expected observables recorded.")
        telemetry_lines.append("")

    detection_lines = ["# Detection Validation", ""]
    for step in pack.attack_path:
        detection_lines.extend(
            [
                f"## {step.sequence}. {step.phase}",
                "",
                "### Detection opportunities",
                "",
                _bullets(step.detection_opportunities),
                "",
                "### Evidence to capture",
                "",
                _bullets(step.evidence_to_capture),
                "",
            ]
        )

    cleanup_lines = ["# Stop Conditions and Cleanup", ""]
    for step in pack.attack_path:
        cleanup_lines.extend(
            [
                f"## {step.sequence}. {step.phase}",
                "",
                "### Stop conditions",
                "",
                _bullets(step.stop_conditions),
                "",
                "### Cleanup",
                "",
                _bullets(step.cleanup),
                "",
            ]
        )

    readme = f"""# {pack.title} — Operator Pack

This directory is an operator-oriented view of stored run `{run_id}`. It remains
a planning artifact: exercise execution requires the approvals and boundaries in
the source run. `full_report.html` is the evidence-oriented report.

Files are numbered in suggested reading order. Verify `operator_manifest.json`
before distribution.
"""
    files = {
        "README.md": readme.encode(),
        "00_Executive_Summary.md": summary.encode(),
        "01_Operator_Injects.md": "\n".join(inject_lines).encode(),
        "02_Authorized_Safe_Actions.md": "\n".join(action_lines).encode(),
        "03_Expected_Telemetry.md": "\n".join(telemetry_lines).encode(),
        "04_Detection_Validation.md": "\n".join(detection_lines).encode(),
        "05_Stop_Conditions_Cleanup.md": "\n".join(cleanup_lines).encode(),
        "full_report.html": render_html(pack).encode(),
    }
    manifest = {
        "schema_version": 1,
        "source_run_id": run_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "safety_gate_passed": pack.qa.safety_gate_passed,
        "files": {
            name: {"sha256": sha256_bytes(content), "bytes": len(content)}
            for name, content in files.items()
        },
    }
    files["operator_manifest.json"] = (
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    ).encode()
    return files


def write_operator_pack(
    pack: ScenarioPack,
    *,
    run_id: str,
    output: Path,
    zipped: bool = False,
    force: bool = False,
) -> Path:
    destination = output.with_suffix(".zip") if zipped and output.suffix != ".zip" else output
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; use --force to overwrite")
    files = operator_files(pack, run_id=run_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if zipped:
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        try:
            with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
                for name, content in files.items():
                    archive.writestr(name, content)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    staging = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    staging.mkdir()
    try:
        for name, content in files.items():
            atomic_write_bytes(staging / name, content)
        if destination.exists():
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        os.replace(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return destination
