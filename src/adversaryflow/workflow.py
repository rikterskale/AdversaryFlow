"""End-to-end local purple-team workflow using synthetic harness events only."""

import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ai import AICampaignDraft, validate_ai_draft
from .audit import AuditLog, sha256_bytes
from .emulation import Ability
from .models import RulesOfEngagement
from .loopback import LoopbackSink


@dataclass(frozen=True)
class Approval:
    approval_id: str
    approver: str
    plan_hash: str
    approved_at: str
    decision: str
    scope_acknowledged: bool = True


def approve_draft(draft: AICampaignDraft, roe: RulesOfEngagement, abilities: tuple[Ability, ...], approver: str, plan_hash: str, decision: str = "approved") -> Approval:
    validate_ai_draft(draft, roe, abilities)
    if approver != roe.approver_name:
        raise PermissionError("Only the approver named in the RoE may approve this draft")
    if decision not in {"approved", "rejected"}:
        raise ValueError("decision must be approved or rejected")
    return Approval(str(uuid.uuid4()), approver, plan_hash, datetime.now(timezone.utc).isoformat(), decision)


def run_local_emulation(draft: AICampaignDraft, abilities: tuple[Ability, ...], approval: Approval, output_root: str | Path = "artifacts/runs") -> Path:
    if approval.decision != "approved":
        raise PermissionError("Cannot emulate a rejected draft")
    selected = [a for a in abilities if a.id in draft.ability_ids]
    run_dir = Path(output_root) / f"run-{uuid.uuid4()}"
    run_dir.mkdir(parents=True, exist_ok=False)
    events = []
    with LoopbackSink() as sink:
        for ability in selected:
            observed = []
            if ability.network_scope == "loopback":
                sink.send_marker(run_dir.name)
                observed = sink.received
            events.append({"event": "simulation_completed", "ability_id": ability.id, "technique_id": ability.technique_id, "target": draft.target, "behavior_success": True, "telemetry": [asdict(t) for t in ability.expected_telemetry], "observed_loopback_requests": observed, "network_scope": ability.network_scope, "execution": "synthetic-harness-only"})
    event_bytes = ("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n").encode()
    (run_dir / "events.jsonl").write_bytes(event_bytes)
    (run_dir / "draft.json").write_text(json.dumps(draft.as_dict(), indent=2), encoding="utf-8")
    manifest = {"run_id": run_dir.name, "approval": asdict(approval), "events_sha256": sha256_bytes(event_bytes), "mode": "local-synthetic"}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    AuditLog(run_dir / "audit.jsonl").record("local_emulation_completed", run_id=run_dir.name, approval_id=approval.approval_id, ability_count=len(selected))
    return run_dir


def build_gap_report(run_dir: str | Path) -> dict[str, Any]:
    root = Path(run_dir)
    events = [json.loads(line) for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    expected = {(item["category"], item["description"]) for event in events for item in event.get("telemetry", []) if item.get("required", True)}
    observed = {(item["category"], item["description"]) for event in events for item in event.get("telemetry", [])}
    gaps = [{"category": c, "description": d, "status": "missing"} for c, d in sorted(expected - observed)]
    report = {"run_id": root.name, "behavior_success": all(event.get("behavior_success") for event in events), "telemetry_expected": len(expected), "telemetry_observed": len(observed), "detection_gap_count": len(gaps), "gaps": gaps, "assessment": "Telemetry recorded by synthetic harness; validate separately against production log pipelines."}
    (root / "telemetry-gap-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
