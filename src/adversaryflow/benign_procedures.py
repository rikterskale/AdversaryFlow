"""Fixed, local, reversible procedures for defensive telemetry validation."""

import json
import platform
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4


def catalog() -> dict[str, Any]:
    return json.loads(files("adversaryflow.resources").joinpath("benign_procedures.json").read_text(encoding="utf-8"))


def _root(value: str | Path) -> Path:
    root = Path(value).resolve()
    try: root.relative_to(Path.cwd().resolve())
    except ValueError as exc: raise ValueError("Procedure artifacts must remain inside the current working directory") from exc
    return root


def run(procedure_ids: list[str], output_root: str | Path = "artifacts/benign-procedures", actor_profile: dict[str, Any] | None = None, retest_of: str | None = None) -> dict[str, Any]:
    available = {item["id"]: item for item in catalog()["procedures"]}
    if not isinstance(procedure_ids, list) or not procedure_ids or any(item not in available for item in procedure_ids): raise ValueError("procedure_ids must select one or more approved benign procedures")
    run_id = f"benign-procedure-{uuid4()}"; root = _root(output_root) / run_id; work = root / "work"; work.mkdir(parents=True)
    selected = [available[item] for item in procedure_ids]; now = datetime.now(timezone.utc).isoformat(); events = []
    for item in selected:
        artifact = work / f"{item['id']}.json"
        payload = {"procedure_id": item["id"], "technique_id": item["technique_id"], "source": item["source"], "executed_at": now, "synthetic": True, "action": item["action"], "boundary": "run-owned local artifact only"}
        if item["id"] == "procedure-local-inventory": payload["platform"] = platform.platform()
        if item["id"] == "procedure-dummy-data-read": payload["dummy_record"] = "TEST-PAN-0000-0000-0000-0000"
        if item["id"] == "procedure-canary-rename":
            canary = work / "canary.validation"; canary.write_text("run-owned benign canary", encoding="utf-8"); canary.rename(work / "canary.validation.checked")
        artifact.write_text(json.dumps(payload, indent=2), encoding="utf-8"); events.append(payload)
    (root / "events.jsonl").write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")
    manifest = {"run_id": run_id, "retest_of": retest_of, "actor_profile": actor_profile, "execution_boundary": catalog()["boundary"], "procedures": selected, "cleanup": "Use cleanup to remove only the run-owned work directory after evidence review."}
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"run_id": run_id, "run_dir": str(root), "procedures": selected, "next": "Review local procedure evidence, record observed detections, then clean up only the run-owned work directory."}


def assess(run_dir: str | Path, observed_procedure_ids: list[str]) -> dict[str, Any]:
    root = _root(run_dir); manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8")); expected = {item["id"]: item for item in manifest["procedures"]}; observed = set(observed_procedure_ids) & set(expected)
    gaps = [{"procedure_id": item_id, "technique_id": item["technique_id"], "source": item["source"], "expected_detection": item["expected_detection"], "status": "not-observed"} for item_id, item in expected.items() if item_id not in observed]
    report = {"run_id": manifest["run_id"], "retest_of": manifest.get("retest_of"), "expected_procedure_count": len(expected), "observed_procedure_count": len(observed), "detection_gap_count": len(gaps), "gaps": gaps, "assessment": "Only benign run-owned procedures were performed; this validates detection pathways, not adversary capability."}
    (root / "benign-procedure-gap-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8"); return report


def cleanup(run_dir: str | Path) -> dict[str, Any]:
    root = _root(run_dir); work = root / "work"
    if not work.is_dir(): raise ValueError("Run-owned work directory not found")
    for item in sorted(work.iterdir()): item.unlink()
    work.rmdir(); record = {"run_id": root.name, "cleaned_at": datetime.now(timezone.utc).isoformat(), "scope": "run-owned work directory only"}; (root / "cleanup.json").write_text(json.dumps(record, indent=2), encoding="utf-8"); return record
