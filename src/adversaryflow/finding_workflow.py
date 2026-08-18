"""Finding-driven, resumable workflow engine.

The engine is deliberately domain-neutral: adapters turn observations into
findings, while this module owns lifecycle, gating, prioritisation, guidance,
and auditability.  It is safe to use interactively or from an agent because
all mutations go through the same validated command surface.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FindingStatus(StrEnum):
    OPEN = "open"
    VALIDATED = "validated"
    EXPLOITED = "exploited"
    MITIGATED = "mitigated"
    CLOSED = "closed"
    REJECTED = "rejected"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowPhase(StrEnum):
    SCOPE = "scope"
    AUTHORIZE = "authorize"
    DISCOVER = "discover"
    VALIDATE = "validate"
    ASSESS = "assess"
    MITIGATE = "mitigate"
    VERIFY = "verify"
    REPORT = "report"
    CLOSE = "close"


_SEVERITY_SCORE = {"info": 0, "low": 10, "medium": 30, "high": 60, "critical": 100}
_STATUS_RANK = {FindingStatus.OPEN: 0, FindingStatus.VALIDATED: 1, FindingStatus.EXPLOITED: 2,
                FindingStatus.MITIGATED: 3, FindingStatus.CLOSED: 4, FindingStatus.REJECTED: 4}
_ALLOWED_STATUS = {
    FindingStatus.OPEN: {FindingStatus.VALIDATED, FindingStatus.REJECTED, FindingStatus.CLOSED},
    FindingStatus.VALIDATED: {FindingStatus.EXPLOITED, FindingStatus.MITIGATED, FindingStatus.CLOSED},
    FindingStatus.EXPLOITED: {FindingStatus.MITIGATED},
    FindingStatus.MITIGATED: {FindingStatus.VALIDATED, FindingStatus.CLOSED},
    FindingStatus.CLOSED: set(), FindingStatus.REJECTED: set(),
}


@dataclass
class Finding:
    """A durable observation/result that can influence workflow decisions."""

    title: str
    description: str
    severity: FindingSeverity | str = FindingSeverity.INFO
    category: str = "observation"
    source: str = "user"
    finding_id: str = field(default_factory=lambda: f"finding-{uuid.uuid4()}" )
    status: FindingStatus | str = FindingStatus.OPEN
    confidence: float = 1.0
    priority: float = 0.0
    tags: set[str] = field(default_factory=set)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    related_finding_ids: set[str] = field(default_factory=set)
    linked_step_ids: set[str] = field(default_factory=set)
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = FindingSeverity(str(self.severity).lower())
        self.status = FindingStatus(str(self.status).lower())
        if not 0 <= float(self.confidence) <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if not self.title.strip() or not self.description.strip():
            raise ValueError("finding title and description are required")
        self.recalculate_priority()

    def recalculate_priority(self, *, urgency: float = 1.0, exposure: float = 1.0) -> float:
        self.priority = round(_SEVERITY_SCORE[self.severity.value] * float(self.confidence) * float(urgency) * float(exposure), 2)
        return self.priority

    def add_evidence(self, evidence: Mapping[str, Any], actor: str = "system") -> None:
        if not evidence:
            raise ValueError("evidence cannot be empty")
        self.evidence.append(dict(evidence))
        self.updated_at = _now()
        self.history.append({"event": "evidence_added", "actor": actor, "at": self.updated_at})

    def transition(self, status: FindingStatus | str, actor: str = "system", reason: str = "") -> None:
        target = FindingStatus(str(status).lower())
        if target == self.status:
            return
        if target not in _ALLOWED_STATUS[self.status]:
            raise ValueError(f"invalid finding transition: {self.status.value} -> {target.value}")
        previous = self.status
        self.status = target
        self.updated_at = _now()
        self.history.append({"event": "status_changed", "from": previous.value, "to": target.value,
                             "actor": actor, "reason": reason, "at": self.updated_at})

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["severity"] = self.severity.value
        value["status"] = self.status.value
        for key in ("tags", "related_finding_ids", "linked_step_ids"):
            value[key] = sorted(value[key])
        return value


@dataclass(frozen=True)
class WorkflowStep:
    step_id: str
    phase: WorkflowPhase | str
    title: str
    explanation: str
    required: bool = True
    depends_on: tuple[str, ...] = ()
    required_finding_tags: tuple[str, ...] = ()
    blocked_by_finding_tags: tuple[str, ...] = ()
    action: str = "complete_step"

    def __post_init__(self) -> None:
        object.__setattr__(self, "phase", WorkflowPhase(str(self.phase).lower()))


@dataclass
class Recommendation:
    action_id: str
    title: str
    explanation: str
    step_id: str | None = None
    finding_ids: tuple[str, ...] = ()
    mandatory: bool = False
    priority: float = 0.0
    blocked: bool = False


@dataclass
class WorkflowState:
    workflow_id: str = field(default_factory=lambda: f"workflow-{uuid.uuid4()}" )
    phase: WorkflowPhase = WorkflowPhase.SCOPE
    completed_step_ids: list[str] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    pending_action_ids: list[str] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    audit_log: list[dict[str, Any]] = field(default_factory=list)
    progress_percent: float = 0.0
    status: str = "active"
    metadata: dict[str, Any] = field(default_factory=dict)
    revision: int = 0
    updated_at: str = field(default_factory=_now)

    @property
    def open_findings(self) -> list[Finding]:
        return [f for f in self.findings.values() if f.status not in {FindingStatus.CLOSED, FindingStatus.REJECTED}]

    def as_dict(self) -> dict[str, Any]:
        return {"workflow_id": self.workflow_id, "phase": self.phase.value,
                "completed_step_ids": self.completed_step_ids, "findings": {k: v.as_dict() for k, v in self.findings.items()},
                "pending_action_ids": self.pending_action_ids, "decisions": self.decisions, "audit_log": self.audit_log,
                "progress_percent": self.progress_percent, "status": self.status, "metadata": self.metadata,
                "revision": self.revision, "updated_at": self.updated_at}


class FindingWorkflowEngine:
    """Validated command/query façade for a complete guided workflow."""

    def __init__(self, state: WorkflowState | None = None, steps: Iterable[WorkflowStep] | None = None,
                 *, persistence_path: str | Path | None = None, correlation: Callable[[Finding, Finding], bool] | None = None):
        self.state = state or WorkflowState()
        self.steps = tuple(steps or default_steps())
        self._steps = {s.step_id: s for s in self.steps}
        self._correlation = correlation or self._default_correlation
        self.persistence_path = Path(persistence_path) if persistence_path else None
        self._validate_graph()
        self._recompute()

    def _validate_graph(self) -> None:
        ids = set(self._steps)
        if len(ids) != len(self.steps) or any(set(s.depends_on) - ids for s in self.steps):
            raise ValueError("workflow steps contain duplicate or unknown dependencies")
        # A topological walk makes cycles and unreachable custom graphs explicit.
        visiting: set[str] = set(); visited: set[str] = set()
        def visit(step_id: str) -> None:
            if step_id in visiting: raise ValueError("workflow step dependency cycle")
            if step_id in visited: return
            visiting.add(step_id)
            for dep in self._steps[step_id].depends_on: visit(dep)
            visiting.remove(step_id); visited.add(step_id)
        for step_id in ids: visit(step_id)

    @staticmethod
    def _default_correlation(left: Finding, right: Finding) -> bool:
        return left.finding_id != right.finding_id and bool(set(left.tags) & set(right.tags)) and left.category == right.category

    def _record(self, event: str, **details: Any) -> None:
        self.state.revision += 1; self.state.updated_at = _now()
        self.state.audit_log.append({"event": event, "at": self.state.updated_at, **details})

    def _recompute(self) -> None:
        total = len(self.steps) or 1
        self.state.progress_percent = round(100 * len(self.state.completed_step_ids) / total, 2)
        if self.state.progress_percent >= 100 and not self.state.open_findings:
            self.state.phase, self.state.status = WorkflowPhase.CLOSE, "completed"
        elif self.state.progress_percent >= 100:
            self.state.phase, self.state.status = WorkflowPhase.REPORT, "active"
        else:
            pending = [s for s in self.steps if s.step_id not in self.state.completed_step_ids and not self._is_blocked(s)]
            if pending: self.state.phase = pending[0].phase
        self.state.pending_action_ids = [r.action_id for r in self.recommendations()]

    def _is_blocked(self, step: WorkflowStep) -> bool:
        if any(dep not in self.state.completed_step_ids for dep in step.depends_on): return True
        tags = {tag for f in self.state.open_findings for tag in f.tags}
        return bool(tags & set(step.blocked_by_finding_tags)) or bool(step.required_finding_tags and not (tags & set(step.required_finding_tags)))

    def ingest_finding(self, finding: Finding | Mapping[str, Any], *, actor: str = "system") -> Finding:
        item = finding if isinstance(finding, Finding) else Finding(**dict(finding))
        if item.finding_id in self.state.findings:
            raise ValueError(f"finding already exists: {item.finding_id}")
        for existing in self.state.findings.values():
            if self._correlation(existing, item):
                item.related_finding_ids.add(existing.finding_id); existing.related_finding_ids.add(item.finding_id)
        self.state.findings[item.finding_id] = item
        self._record("finding_created", actor=actor, finding_id=item.finding_id, status=item.status.value, priority=item.priority)
        self._recompute(); self.persist()
        return item

    def update_finding(self, finding_id: str, *, actor: str = "system", status: FindingStatus | str | None = None,
                       evidence: Mapping[str, Any] | None = None, confidence: float | None = None,
                       tags: Iterable[str] | None = None, reason: str = "") -> Finding:
        item = self._finding(finding_id)
        if status is not None: item.transition(status, actor, reason)
        if evidence is not None: item.add_evidence(evidence, actor)
        if confidence is not None:
            if not 0 <= confidence <= 1: raise ValueError("confidence must be between 0 and 1")
            item.confidence = confidence; item.recalculate_priority(); item.updated_at = _now()
        if tags is not None: item.tags.update(map(str, tags)); item.updated_at = _now()
        self._record("finding_updated", actor=actor, finding_id=finding_id)
        self._recompute(); self.persist(); return item

    def complete_step(self, step_id: str, *, actor: str = "operator", decision: str | None = None, notes: str = "") -> None:
        step = self._steps.get(step_id)
        if step is None: raise KeyError(f"unknown workflow step: {step_id}")
        if step_id in self.state.completed_step_ids: return
        if step.phase == WorkflowPhase.CLOSE and self.state.open_findings:
            raise ValueError("cannot close workflow while findings remain open")
        if self._is_blocked(step): raise ValueError(f"step is blocked: {step_id}")
        self.state.completed_step_ids.append(step_id)
        if decision is not None: self.state.decisions.append({"step_id": step_id, "decision": decision, "notes": notes, "actor": actor, "at": _now()})
        self._record("step_completed", actor=actor, step_id=step_id, decision=decision)
        self._recompute(); self.persist()

    def recommendations(self) -> list[Recommendation]:
        results: list[Recommendation] = []
        for finding in sorted(self.state.open_findings, key=lambda f: f.priority, reverse=True):
            if finding.status == FindingStatus.OPEN:
                results.append(Recommendation("validate:" + finding.finding_id, "Validate finding", "Confirm evidence and scope before acting.", finding_ids=(finding.finding_id,), mandatory=finding.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}, priority=finding.priority))
            elif finding.status in {FindingStatus.VALIDATED, FindingStatus.EXPLOITED}:
                results.append(Recommendation("mitigate:" + finding.finding_id, "Mitigate finding", "Apply and record an approved remediation, then verify it.", finding_ids=(finding.finding_id,), mandatory=True, priority=finding.priority))
        for step in self.steps:
            if step.step_id not in self.state.completed_step_ids:
                blocked = self._is_blocked(step)
                if not blocked:
                    results.append(Recommendation("step:" + step.step_id, step.title, step.explanation, step.step_id, priority=1))
                break
        return sorted(results, key=lambda r: (not r.mandatory, -r.priority))

    def query_findings(self, *, status: FindingStatus | str | None = None, tag: str | None = None,
                       minimum_priority: float = 0) -> list[Finding]:
        target = FindingStatus(str(status).lower()) if status is not None else None
        return sorted((f for f in self.state.findings.values() if (target is None or f.status == target) and (tag is None or tag in f.tags) and f.priority >= minimum_priority), key=lambda f: f.priority, reverse=True)

    def _finding(self, finding_id: str) -> Finding:
        try: return self.state.findings[finding_id]
        except KeyError: raise KeyError(f"unknown finding: {finding_id}") from None

    def persist(self) -> None:
        if self.persistence_path:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.persistence_path.with_suffix(self.persistence_path.suffix + ".tmp")
            temp.write_text(json.dumps(self.state.as_dict(), indent=2), encoding="utf-8")
            temp.replace(self.persistence_path)

    @classmethod
    def resume(cls, persistence_path: str | Path, *, steps: Iterable[WorkflowStep] | None = None) -> "FindingWorkflowEngine":
        data = json.loads(Path(persistence_path).read_text(encoding="utf-8"))
        findings = {key: Finding(**{**value, "severity": value["severity"], "status": value["status"], "tags": set(value.get("tags", [])), "related_finding_ids": set(value.get("related_finding_ids", [])), "linked_step_ids": set(value.get("linked_step_ids", []))}) for key, value in data.get("findings", {}).items()}
        state = WorkflowState(workflow_id=data["workflow_id"], phase=WorkflowPhase(data["phase"]), completed_step_ids=list(data.get("completed_step_ids", [])), findings=findings, pending_action_ids=list(data.get("pending_action_ids", [])), decisions=list(data.get("decisions", [])), audit_log=list(data.get("audit_log", [])), progress_percent=float(data.get("progress_percent", 0)), status=data.get("status", "active"), metadata=dict(data.get("metadata", {})), revision=int(data.get("revision", 0)), updated_at=data.get("updated_at", _now()))
        return cls(state, steps, persistence_path=persistence_path)


def default_steps() -> tuple[WorkflowStep, ...]:
    return tuple(WorkflowStep(step_id, phase, title, explanation, depends_on=deps) for step_id, phase, title, explanation, deps in (
        ("scope", WorkflowPhase.SCOPE, "Define scope", "Record objective, targets, exclusions, and ownership.", ()),
        ("authorize", WorkflowPhase.AUTHORIZE, "Confirm authorization", "Verify approval and operating constraints before discovery.", ("scope",)),
        ("discover", WorkflowPhase.DISCOVER, "Collect observations", "Run approved discovery or import observations.", ("authorize",)),
        ("validate", WorkflowPhase.VALIDATE, "Validate findings", "Confirm evidence, confidence, and affected scope.", ("discover",)),
        ("assess", WorkflowPhase.ASSESS, "Assess impact", "Correlate findings and prioritize risk.", ("validate",)),
        ("mitigate", WorkflowPhase.MITIGATE, "Plan remediation", "Record accepted remediation or risk decision for each actionable finding.", ("assess",)),
        ("verify", WorkflowPhase.VERIFY, "Verify outcomes", "Retest mitigations and capture residual risk.", ("mitigate",)),
        ("report", WorkflowPhase.REPORT, "Produce final report", "Summarize evidence, decisions, residual risk, and actions.", ("verify",)),
        ("close", WorkflowPhase.CLOSE, "Close and archive", "Confirm no unresolved mandatory action remains and archive the audit trail.", ("report",)),
    ))


__all__ = ["Finding", "FindingSeverity", "FindingStatus", "Recommendation", "WorkflowPhase", "WorkflowState", "WorkflowStep", "FindingWorkflowEngine", "default_steps"]
