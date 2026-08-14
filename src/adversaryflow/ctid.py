"""Benign CTID/ATT&CK vocabulary and fixture evidence for defensive validation."""

import json
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any
from uuid import uuid4


def fixtures() -> dict[str, Any]:
    return json.loads(files("adversaryflow.resources").joinpath("ctid_apt29_identity_fixtures.json").read_text(encoding="utf-8"))


def _root(path: str | Path) -> Path:
    root = Path(path).resolve()
    try:
        root.relative_to(Path.cwd().resolve())
    except ValueError as exc:
        raise ValueError("CTID fixture artifacts must remain inside the current working directory") from exc
    return root


def create_fixture_bundle(output_root: str | Path = "artifacts/ctid-fixtures", retest_of: str | None = None, fixture_ids: list[str] | None = None, actor_profile: dict[str, Any] | None = None) -> dict[str, Any]:
    root = _root(output_root); run_id = f"ctid-fixture-{uuid4()}"; bundle = root / run_id; bundle.mkdir(parents=True, exist_ok=False)
    catalog = fixtures(); emitted_at = datetime.now(timezone.utc).isoformat()
    allowed = {item["id"]: item for item in catalog["fixtures"]}
    selected_ids = fixture_ids or list(allowed)
    if not selected_ids or any(item not in allowed for item in selected_ids):
        raise ValueError("fixture_ids must select one or more pre-registered benign fixtures")
    selected = [allowed[item] for item in selected_ids]
    events = [{"fixture_id": item["id"], "event_type": item["event_type"], "source": item["source"], "technique_id": item["technique_id"], "synthetic": True, "emitted_at": emitted_at, "notice": "Benign pre-registered fixture only; no identity, cloud, or endpoint action was performed."} for item in selected]
    (bundle / "fixtures.jsonl").write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")
    manifest = {"run_id": run_id, "created_at": emitted_at, "retest_of": retest_of, "actor_profile": actor_profile, "execution_boundary": "fixture-only; no identity, cloud, endpoint, or network action", "vocabulary": catalog["vocabulary"], "fixtures": selected, "import_instruction": "Import fixtures.jsonl through the lab's approved telemetry replay or test-ingestion path; do not treat it as a production event source."}
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"run_id": run_id, "bundle": str(bundle), "fixtures": selected, "next": "Import the local JSONL through an approved lab-only replay path, then record the detections that appeared."}


def assess_fixture_evidence(bundle_path: str | Path, observed_fixture_ids: list[str]) -> dict[str, Any]:
    bundle = _root(bundle_path); manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    expected = {item["id"]: item for item in manifest["fixtures"]}; observed = {item for item in observed_fixture_ids if item in expected}
    gaps = [{"fixture_id": fixture_id, "technique_id": item["technique_id"], "source": item["source"], "expected_detection": item["expected_detection"], "rule_guidance": item["rule_guidance"], "status": "not-observed"} for fixture_id, item in expected.items() if fixture_id not in observed]
    report = {"run_id": manifest["run_id"], "retest_of": manifest.get("retest_of"), "expected_fixture_count": len(expected), "observed_fixture_count": len(observed), "detection_gap_count": len(gaps), "observed_fixture_ids": sorted(observed), "gaps": gaps, "assessment": "This measures reported lab detections for benign fixture events only; it does not demonstrate an identity compromise or production detection coverage."}
    (bundle / "ctid-detection-gap-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    timeline = ["# CTID Fixture Training Timeline", "", f"- Run: {manifest['run_id']}", f"- Retest of: {manifest.get('retest_of') or 'baseline'}", "- Boundary: benign fixture-only validation", f"- Expected: {len(expected)}", f"- Observed: {len(observed)}", f"- Gaps: {len(gaps)}", "", "## Analyst discussion", "", "Review each observed event, its source context, detection latency, triage decision, and the rule guidance for any gap."]
    (bundle / "training-timeline.md").write_text("\n".join(timeline) + "\n", encoding="utf-8")
    return report
