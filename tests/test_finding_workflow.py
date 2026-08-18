import json

import pytest

from adversaryflow import (Finding, FindingSeverity, FindingStatus,
                           FindingWorkflowEngine, WorkflowPhase)


def _engine(tmp_path):
    return FindingWorkflowEngine(persistence_path=tmp_path / "workflow.json")


def test_complete_guided_lifecycle_and_persistence(tmp_path):
    engine = _engine(tmp_path)
    assert engine.state.phase == WorkflowPhase.SCOPE
    for step in ("scope", "authorize", "discover"):
        engine.complete_step(step)
    finding = engine.ingest_finding(Finding("Missing signal", "Expected telemetry was absent", FindingSeverity.HIGH, tags={"telemetry", "gap"}))
    assert engine.state.open_findings == [finding]
    assert engine.recommendations()[0].mandatory is True
    engine.update_finding(finding.finding_id, status="validated", evidence={"event_id": "evt-1"})
    engine.update_finding(finding.finding_id, status="mitigated", reason="rule deployed")
    engine.update_finding(finding.finding_id, status="closed")
    for step in ("validate", "assess", "mitigate", "verify", "report", "close"):
        engine.complete_step(step)
    assert engine.state.status == "completed"
    assert engine.state.progress_percent == 100
    resumed = FindingWorkflowEngine.resume(tmp_path / "workflow.json")
    assert resumed.state.status == "completed"
    assert resumed.state.findings[finding.finding_id].status == FindingStatus.CLOSED
    assert json.loads((tmp_path / "workflow.json").read_text())["revision"] > 0


def test_branching_blocking_and_user_injected_finding(tmp_path):
    engine = _engine(tmp_path)
    for step in ("scope", "authorize", "discover", "validate", "assess"):
        engine.complete_step(step)
    finding = engine.ingest_finding({"title": "Risk", "description": "Observed issue", "severity": "medium", "tags": {"needs-remediation"}})
    with pytest.raises(ValueError, match="open"):
        engine.complete_step("close")
    with pytest.raises(ValueError, match="invalid finding transition"):
        engine.update_finding(finding.finding_id, status="exploited")
    engine.update_finding(finding.finding_id, status="validated")
    assert any(rec.action_id.startswith("mitigate:") for rec in engine.recommendations())
    assert engine.query_findings(tag="needs-remediation", minimum_priority=1)[0].finding_id == finding.finding_id


def test_correlation_and_evidence_history(tmp_path):
    engine = _engine(tmp_path)
    first = engine.ingest_finding(Finding("A", "one", category="detection", tags={"T1"}))
    second = engine.ingest_finding(Finding("B", "two", category="detection", tags={"T1", "T2"}))
    assert second.finding_id in first.related_finding_ids
    engine.update_finding(first.finding_id, evidence={"source": "operator"}, confidence=0.5, tags=["confirmed"])
    assert first.evidence and first.confidence == 0.5
    assert any(event["event"] == "status_changed" for event in engine.state.findings[first.finding_id].history) is False
    assert any(event["event"] == "finding_updated" for event in engine.state.audit_log)


def test_custom_graph_rejects_cycles_and_unknown_dependencies():
    from adversaryflow.finding_workflow import WorkflowStep
    with pytest.raises(ValueError, match="unknown"):
        FindingWorkflowEngine(steps=[WorkflowStep("a", WorkflowPhase.SCOPE, "A", "", depends_on=("missing",))])
    with pytest.raises(ValueError, match="cycle"):
        FindingWorkflowEngine(steps=[WorkflowStep("a", WorkflowPhase.SCOPE, "A", "", depends_on=("b",)), WorkflowStep("b", WorkflowPhase.SCOPE, "B", "", depends_on=("a",))])


def test_finding_validation_and_idempotent_operations(tmp_path):
    with pytest.raises(ValueError, match="confidence"):
        Finding("bad", "bad", confidence=2)
    with pytest.raises(ValueError, match="title"):
        Finding("", "bad")
    finding = Finding("valid", "valid")
    with pytest.raises(ValueError, match="evidence"):
        finding.add_evidence({})
    assert finding.transition("open") is None
    engine = _engine(tmp_path)
    engine.ingest_finding(finding)
    with pytest.raises(ValueError, match="already exists"):
        engine.ingest_finding(finding)
    with pytest.raises(KeyError, match="unknown finding"):
        engine.update_finding("missing", confidence=0.5)
    with pytest.raises(KeyError, match="unknown workflow step"):
        engine.complete_step("missing")


def test_custom_finding_gates_and_no_persistence_engine():
    from adversaryflow.finding_workflow import WorkflowStep
    steps = [
        WorkflowStep("start", WorkflowPhase.SCOPE, "Start", "begin"),
        WorkflowStep("gated", WorkflowPhase.VALIDATE, "Gated", "needs proof", depends_on=("start",), required_finding_tags=("proof",)),
    ]
    engine = FindingWorkflowEngine(steps=steps)
    engine.complete_step("start")
    assert not any(rec.step_id == "gated" for rec in engine.recommendations())
    finding = engine.ingest_finding(Finding("proof", "proof", tags={"proof"}))
    assert any(rec.step_id == "gated" for rec in engine.recommendations())
    engine.update_finding(finding.finding_id, tags=["extra"])
    assert engine.state.pending_action_ids
