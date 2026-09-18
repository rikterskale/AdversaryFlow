"""Generate non-executable purple-team engagement reports.

Reports are built from a catalog-rebound AdversaryFlow plan.  They contain
coverage, expected telemetry, and evidence metadata, but deliberately omit
command bodies and cannot execute anything.
"""
from __future__ import annotations

import hashlib
import html
import io
import json
import re
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, ClassVar, Dict, Iterable, List, Mapping, Sequence, Tuple
from urllib.parse import urlparse

from .execution_kit import ExecutionKitError, normalize_plan, rebind_to_catalog

OUTCOMES = {"not_run", "passed", "failed", "skipped"}
DETECTION_RESULTS = {"not_assessed", "alerted", "silent", "blocked", "not_instrumented"}


class ReportError(ExecutionKitError):
    """The submitted plan cannot safely produce an engagement report."""


@dataclass(frozen=True)
class SigmaReference:
    label: str
    url: str


@dataclass(frozen=True)
class TelemetryAcceptance:
    technique_id: str
    scenario: str
    activity_event_types: Tuple[str, ...]
    minimum_activity_events: int
    requirements: Tuple[str, ...]
    limitation: str


@dataclass(frozen=True)
class ReportExecution:
    outcome: str
    updated_at: str
    operator: str
    target: str
    notes: str
    cleanup_completed: bool | None
    run_id: str
    started_at: str
    completed_at: str
    exit_code: int | None
    stdout_sha256: str
    stderr_sha256: str
    receipt_sha256: str
    receipt_verified: bool | None
    telemetry_references: Tuple[str, ...]
    evidence_source: str
    detection_result: str


@dataclass(frozen=True)
class ReportTechnique:
    sequence: int
    tactic: str
    tactic_title: str
    technique_id: str
    technique_name: str
    attack_url: str
    platform: str
    command_source: str
    supported: bool
    fidelity: str
    risk: str
    expected_telemetry: str
    telemetry_acceptance: TelemetryAcceptance | None
    data_sources: Tuple[str, ...]
    detection_guidance: str
    sigma_references: Tuple[SigmaReference, ...]
    execution: ReportExecution

    @property
    def outcome(self) -> str:
        return self.execution.outcome

    @property
    def detection_result(self) -> str:
        return self.execution.detection_result

    @property
    def evidence_source(self) -> str:
        return self.execution.evidence_source

    @property
    def evidence_notes(self) -> str:
        return self.execution.notes

    @property
    def telemetry_references(self) -> Tuple[str, ...]:
        return self.execution.telemetry_references


@dataclass(frozen=True)
class CoverageGap:
    category: str
    technique_id: str
    technique_name: str
    detail: str


@dataclass(frozen=True)
class ReportScope:
    command_platform: str
    include_pre: bool
    curated_only: bool
    allow_network: bool
    allow_admin: bool
    allow_high_risk: bool
    stages: Tuple[str, ...]


@dataclass(frozen=True)
class CoverageSummary:
    occurrences: int
    unique_techniques: int
    supported: int
    unsupported: int
    curated: int
    fallback: int
    outcome_not_run: int
    outcome_passed: int
    outcome_failed: int
    outcome_skipped: int
    detection_not_assessed: int
    detection_alerted: int
    detection_blocked: int
    detection_silent: int
    detection_not_instrumented: int
    expected_telemetry_mapped: int
    attack_detection_mapped: int
    sigma_mapped: int

    @property
    def detected(self) -> int:
        """Positive control results without collapsing their recorded state."""
        return self.detection_alerted + self.detection_blocked


@dataclass(frozen=True)
class EngagementReport:
    schema_version: str
    tool_version: str
    domains: Tuple[str, ...]
    actor_stix_id: str
    actor_id: str
    actor_name: str
    actor_type: str
    actor_aliases: Tuple[str, ...]
    actor_description: str
    actor_technique_count: int
    generated: str
    data_version: str
    platform: str
    scope: ReportScope
    operator: str
    target: str
    execution_started_at: str
    execution_completed_at: str
    plan_sha256: str
    techniques: Tuple[ReportTechnique, ...]
    coverage: CoverageSummary
    gaps: Tuple[CoverageGap, ...]

    @property
    def report_generated(self) -> str:
        """Compatibility alias for renderers; report output adds no wall-clock time."""
        return self.generated

    @property
    def unique_techniques(self) -> int:
        return self.coverage.unique_techniques

    @property
    def recorded(self) -> int:
        return self.coverage.occurrences - self.coverage.outcome_not_run

    @property
    def detection_assessed(self) -> int:
        return self.coverage.occurrences - self.coverage.detection_not_assessed

    @property
    def alerted(self) -> int:
        return self.coverage.detection_alerted


def _text(value: Any, *, maximum: int = 10_000) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", "").strip()[:maximum]


def _text_list(value: Any, *, maximum_items: int = 100, maximum: int = 2_000) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    cleaned = (_text(item, maximum=maximum) for item in value[:maximum_items])
    return tuple(dict.fromkeys(item for item in cleaned if item))


def _safe_https_url(value: Any) -> str:
    url = _text(value, maximum=2_000)
    parsed = urlparse(url)
    return url if parsed.scheme == "https" and bool(parsed.netloc) else ""


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _digest(value: Any) -> str:
    text = _text(value, maximum=64)
    return text.lower() if re.fullmatch(r"[a-fA-F0-9]{64}", text) else ""


def _date_time(value: Any) -> str:
    text = _text(value, maximum=100)
    if not text:
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return text


def _evidence(technique: Mapping[str, Any]) -> ReportExecution:
    raw = technique.get("execution")
    evidence = raw if isinstance(raw, dict) else {}
    outcome = _text(evidence.get("outcome"), maximum=30)
    if outcome not in OUTCOMES:
        outcome = "not_run"
    detection = _text(evidence.get("detection_result"), maximum=40)
    if detection not in DETECTION_RESULTS:
        detection = "not_assessed"
    source = _text(evidence.get("evidence_source"), maximum=60)
    notes = _text(evidence.get("notes"), maximum=500)
    telemetry = _text_list(evidence.get("telemetry_refs"), maximum_items=20, maximum=500)
    return ReportExecution(
        outcome=outcome,
        updated_at=_date_time(evidence.get("updated_at")),
        operator=_text(evidence.get("operator"), maximum=120),
        target=_text(evidence.get("target"), maximum=200),
        notes=notes,
        cleanup_completed=_optional_bool(evidence.get("cleanup_completed")),
        run_id=_text(evidence.get("run_id"), maximum=128),
        started_at=_date_time(evidence.get("started_at")),
        completed_at=_date_time(evidence.get("completed_at")),
        exit_code=_optional_int(evidence.get("exit_code")),
        stdout_sha256=_digest(evidence.get("stdout_sha256")),
        stderr_sha256=_digest(evidence.get("stderr_sha256")),
        receipt_sha256=_digest(evidence.get("receipt_sha256")),
        receipt_verified=_optional_bool(evidence.get("receipt_verified")),
        telemetry_references=telemetry,
        evidence_source=source,
        detection_result=detection,
    )


def _telemetry_acceptance(command: Mapping[str, Any]) -> TelemetryAcceptance | None:
    raw = command.get("telemetry_acceptance")
    if not isinstance(raw, dict):
        return None
    technique_id = _text(raw.get("technique_id"), maximum=64)
    scenario = _text(raw.get("scenario"), maximum=200)
    activity_types = _text_list(raw.get("activity_event_types"), maximum_items=100, maximum=200)
    requirements = _text_list(raw.get("requirements"), maximum_items=100, maximum=2_000)
    minimum = _optional_int(raw.get("minimum_activity_events"))
    limitation = _text(raw.get("limitation"), maximum=2_000)
    if not technique_id or not scenario or not activity_types or not requirements or minimum is None or minimum < 1 or not limitation:
        return None
    return TelemetryAcceptance(
        technique_id=technique_id,
        scenario=scenario,
        activity_event_types=activity_types,
        minimum_activity_events=minimum,
        requirements=requirements,
        limitation=limitation,
    )


def _coverage_gaps(techniques: Iterable[ReportTechnique]) -> Tuple[CoverageGap, ...]:
    gaps: List[CoverageGap] = []
    for item in techniques:
        if not item.supported:
            gaps.append(CoverageGap("Catalog coverage", item.technique_id, item.technique_name,
                                    f"No runnable {_label(item.platform)} catalog exercise is available in this scope."))
        elif item.command_source == "fallback":
            gaps.append(CoverageGap("Catalog fidelity", item.technique_id, item.technique_name,
                                    "This step uses the bounded fallback exercise rather than a keyed curated mapping."))
        if item.outcome in {"not_run", "skipped", "failed"}:
            labels = {"not_run": "has not been run", "skipped": "was skipped", "failed": "did not complete successfully"}
            gaps.append(CoverageGap("Execution coverage", item.technique_id, item.technique_name,
                                    f"The planned technique {labels[item.outcome]}."))
        if item.detection_result in {"not_assessed", "silent", "not_instrumented"}:
            labels = {
                "not_assessed": "Detection was not assessed.",
                "silent": "No detection alerted during the recorded exercise.",
                "not_instrumented": "The lab was not instrumented to validate detection.",
            }
            gaps.append(CoverageGap("Detection validation", item.technique_id, item.technique_name,
                                    labels[item.detection_result]))
        if not item.expected_telemetry:
            gaps.append(CoverageGap("Telemetry mapping", item.technique_id, item.technique_name,
                                    "The catalog does not declare expected telemetry for this technique."))
        if not item.detection_guidance:
            gaps.append(CoverageGap("ATT&CK detection mapping", item.technique_id, item.technique_name,
                                    "The exported ATT&CK record does not contain detection guidance."))
        if not item.sigma_references:
            gaps.append(CoverageGap("Sigma mapping", item.technique_id, item.technique_name,
                                    "The catalog does not carry a Sigma rule reference for this technique."))
    return tuple(gaps)


def _coverage_summary(techniques: Sequence[ReportTechnique]) -> CoverageSummary:
    return CoverageSummary(
        occurrences=len(techniques),
        unique_techniques=len({item.technique_id for item in techniques}),
        supported=sum(item.supported for item in techniques),
        unsupported=sum(not item.supported for item in techniques),
        curated=sum(item.command_source == "curated" for item in techniques),
        fallback=sum(item.command_source == "fallback" for item in techniques),
        outcome_not_run=sum(item.outcome == "not_run" for item in techniques),
        outcome_passed=sum(item.outcome == "passed" for item in techniques),
        outcome_failed=sum(item.outcome == "failed" for item in techniques),
        outcome_skipped=sum(item.outcome == "skipped" for item in techniques),
        detection_not_assessed=sum(item.detection_result == "not_assessed" for item in techniques),
        detection_alerted=sum(item.detection_result == "alerted" for item in techniques),
        detection_blocked=sum(item.detection_result == "blocked" for item in techniques),
        detection_silent=sum(item.detection_result == "silent" for item in techniques),
        detection_not_instrumented=sum(item.detection_result == "not_instrumented" for item in techniques),
        expected_telemetry_mapped=sum(bool(item.expected_telemetry) for item in techniques),
        attack_detection_mapped=sum(bool(item.detection_guidance) for item in techniques),
        sigma_mapped=sum(bool(item.sigma_references) for item in techniques),
    )


def _execution_window(techniques: Sequence[ReportTechnique]) -> Tuple[str, str]:
    def ordered(values: Iterable[str]) -> List[Tuple[datetime, str]]:
        result = []
        for value in values:
            if not value:
                continue
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            result.append((parsed.astimezone(timezone.utc), value))
        return sorted(result, key=lambda item: item[0])

    starts = ordered(item.execution.started_at for item in techniques)
    completions = ordered(item.execution.completed_at for item in techniques)
    return (starts[0][1] if starts else "", completions[-1][1] if completions else "")


def _source_plan_sha256(document: Mapping[str, Any]) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_report(document: Mapping[str, Any]) -> EngagementReport:
    """Validate a plan and build a command-free report model."""
    try:
        rebound = rebind_to_catalog(document)
        normalized = normalize_plan(rebound, require_executable=False)
    except ExecutionKitError as exc:
        raise ReportError(str(exc)) from exc

    actor = rebound.get("actor")
    if not isinstance(actor, dict):
        raise ReportError("Plan actor metadata is incomplete")
    report_rows: List[ReportTechnique] = []
    step_index = 0
    for stage in rebound.get("stages", []):
        if not isinstance(stage, dict):
            continue
        for technique in stage.get("techniques", []):
            if not isinstance(technique, dict) or step_index >= len(normalized.steps):
                raise ReportError("Plan technique metadata is incomplete")
            step = normalized.steps[step_index]
            step_index += 1
            command = technique.get("command")
            command = command if isinstance(command, dict) else {}
            report_rows.append(ReportTechnique(
                sequence=step.sequence,
                tactic=step.tactic,
                tactic_title=step.tactic_title,
                technique_id=step.technique_id,
                technique_name=step.technique_name,
                attack_url=_safe_https_url(technique.get("url")),
                platform=step.platform,
                command_source=step.command_source,
                supported=step.supported,
                fidelity=step.fidelity,
                risk=step.risk,
                expected_telemetry=step.expected_telemetry,
                telemetry_acceptance=_telemetry_acceptance(command),
                data_sources=_text_list(technique.get("data_sources")),
                detection_guidance=_text(technique.get("detection")),
                # The current catalog declares no Sigma-reference field. Keep
                # this empty until such metadata is added to the catalog and
                # the versioned export contract explicitly.
                sigma_references=(),
                execution=_evidence(technique),
            ))
    techniques = tuple(report_rows)
    if not techniques:
        raise ReportError("Plan must contain at least one technique")
    raw_scope = rebound.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    started_at, completed_at = _execution_window(techniques)
    coverage = _coverage_summary(techniques)
    return EngagementReport(
        schema_version=_text(rebound.get("schema_version"), maximum=20),
        tool_version=_text(rebound.get("tool_version"), maximum=100),
        domains=_text_list(rebound.get("domains"), maximum_items=3, maximum=20),
        actor_stix_id=_text(actor.get("stix_id"), maximum=200),
        actor_id=normalized.actor_id,
        actor_name=normalized.actor_name,
        actor_type=_text(actor.get("type"), maximum=20),
        actor_aliases=_text_list(actor.get("aliases"), maximum_items=100, maximum=500),
        actor_description=_text(actor.get("description"), maximum=2_000),
        actor_technique_count=_optional_int(actor.get("technique_count")) or 0,
        generated=normalized.generated,
        data_version=normalized.data_version,
        platform=normalized.platform,
        scope=ReportScope(
            command_platform=normalized.platform,
            include_pre=scope.get("include_pre") is True,
            curated_only=scope.get("curated_only") is True,
            allow_network=scope.get("allow_network") is True,
            allow_admin=scope.get("allow_admin") is True,
            allow_high_risk=scope.get("allow_high_risk") is True,
            stages=_text_list(scope.get("stages"), maximum_items=32, maximum=120),
        ),
        operator=normalized.operator,
        target=normalized.target,
        execution_started_at=started_at,
        execution_completed_at=completed_at,
        plan_sha256=_source_plan_sha256(document),
        techniques=techniques,
        coverage=coverage,
        gaps=_coverage_gaps(techniques),
    )


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-")[:80] or "engagement"


def report_filename(report: EngagementReport, extension: str) -> str:
    stem = f"AdversaryFlow_{_slug(report.actor_id)}_{_slug(report.actor_name)}"
    suffix = "" if extension == "json" else "_report"
    return f"{stem}{suffix}.{extension}"


def render_json(document: Mapping[str, Any]) -> bytes:
    """Serialize the existing schema-versioned plan without a report-shaped fork."""
    try:
        return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReportError("Plan cannot be serialized as JSON") from exc


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _gap_summary(gaps: Sequence[CoverageGap]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for gap in gaps:
        summary[gap.category] = summary.get(gap.category, 0) + 1
    return summary


def _display(value: Any, fallback: str = "Not recorded") -> str:
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _fact(label: str, value: Any, fallback: str = "Not recorded") -> str:
    return f"<li><strong>{_h(label)}:</strong> {_h(_display(value, fallback))}</li>"


def _acceptance_html(acceptance: TelemetryAcceptance | None) -> str:
    if acceptance is None:
        return (
            "<p>No catalog telemetry-acceptance contract is available for this technique. "
            "Validate the expected telemetry against independent sensor data.</p>"
        )
    events = ", ".join(acceptance.activity_event_types)
    requirements = "; ".join(acceptance.requirements)
    return (
        f"<p><strong>Scenario:</strong> {_h(acceptance.scenario)}</p>"
        f"<p><strong>Activity events:</strong> {_h(events)} "
        f"(minimum {_h(acceptance.minimum_activity_events)})</p>"
        f"<p><strong>Requirements:</strong> {_h(requirements)}</p>"
        f'<p class="limitation"><strong>Limitation:</strong> {_h(acceptance.limitation)}</p>'
    )


def _execution_html(execution: ReportExecution) -> str:
    receipt_state = (
        "Digest verified; receipt remains self-reported"
        if execution.receipt_verified is True
        else "Digest not verified" if execution.receipt_verified is False else "Not recorded"
    )
    telemetry = "; ".join(execution.telemetry_references) or "Not recorded"
    facts = (
        _fact("Outcome", _label(execution.outcome))
        + _fact("Detection result", _label(execution.detection_result))
        + _fact("Evidence source", _label(execution.evidence_source) if execution.evidence_source else "")
        + _fact("Operator", execution.operator)
        + _fact("Target", execution.target)
        + _fact("Updated", execution.updated_at)
        + _fact("Started", execution.started_at)
        + _fact("Completed", execution.completed_at)
        + _fact("Exit code", execution.exit_code)
        + _fact("Cleanup completed", execution.cleanup_completed)
        + _fact("Run ID", execution.run_id)
        + _fact("stdout SHA-256", execution.stdout_sha256)
        + _fact("stderr SHA-256", execution.stderr_sha256)
        + _fact("Receipt SHA-256", execution.receipt_sha256)
        + _fact("Receipt status", receipt_state)
        + _fact("Telemetry references", telemetry)
    )
    notes = _h(execution.notes or "No operator evidence note recorded.")
    return f'<p><strong>Notes:</strong> {notes}</p><ul class="facts">{facts}</ul>'


def render_html(report: EngagementReport) -> bytes:
    """Render a self-contained, escaped HTML engagement report."""
    gap_summary = _gap_summary(report.gaps)
    cards = (
        ("Planned", len(report.techniques)),
        ("Unique", report.unique_techniques),
        ("Curated", report.coverage.curated),
        ("Fallback", report.coverage.fallback),
        ("Detected", report.coverage.detected),
        ("Open gaps", len(report.gaps)),
    )
    card_html = "".join(f'<div class="metric"><strong>{value}</strong><span>{_h(label)}</span></div>' for label, value in cards)
    gap_chips = "".join(f'<li><strong>{count}</strong><span>{_h(category)}</span></li>' for category, count in gap_summary.items())
    if not gap_chips:
        gap_chips = '<li class="empty">No coverage gaps were identified from the recorded plan.</li>'

    rows: List[str] = []
    for item in report.techniques:
        sources = ", ".join(item.data_sources) or "Not mapped"
        telemetry = item.expected_telemetry or "Not mapped"
        guidance = item.detection_guidance or "No ATT&CK detection guidance mapped."
        sigma = " · ".join(
            f'<a href="{_h(reference.url)}" rel="noopener noreferrer">{_h(reference.label)}</a>'
            for reference in item.sigma_references
        ) or "No catalog Sigma reference"
        attack_id = f'<a href="{_h(item.attack_url)}" rel="noopener noreferrer">{_h(item.technique_id)}</a>' if item.attack_url else _h(item.technique_id)
        rows.append(f"""
          <article class="technique">
            <div class="technique-head">
              <div><span class="sequence">{item.sequence:02d}</span><h3>{attack_id} · {_h(item.technique_name)}</h3><p>{_h(item.tactic_title)}</p></div>
              <div class="badges"><span class="badge {_h(item.command_source)}">{_h(item.command_source)}</span><span class="badge outcome-{_h(item.outcome)}">{_h(_label(item.outcome))}</span><span class="badge detection-{_h(item.detection_result)}">{_h(_label(item.detection_result))}</span></div>
            </div>
            <div class="technique-grid">
              <section><h4>Expected telemetry</h4><p>{_h(telemetry)}</p><small>ATT&amp;CK data sources: {_h(sources)}</small></section>
              <section><h4>Telemetry acceptance</h4>{_acceptance_html(item.telemetry_acceptance)}</section>
              <section><h4>Detection mapping</h4><p>{_h(guidance)}</p><small>Sigma: {sigma}</small></section>
              <section><h4>Recorded evidence</h4>{_execution_html(item.execution)}</section>
            </div>
          </article>""")

    gap_rows = "".join(
        f'<tr><td><span class="gap-category">{_h(gap.category)}</span></td><td><strong>{_h(gap.technique_id)}</strong><br>{_h(gap.technique_name)}</td><td>{_h(gap.detail)}</td></tr>'
        for gap in report.gaps
    ) or '<tr><td colspan="3" class="empty">No coverage gaps were identified from the recorded plan.</td></tr>'
    description = f'<p class="actor-description">{_h(report.actor_description)}</p>' if report.actor_description else ""
    aliases = ", ".join(report.actor_aliases) or "None recorded"
    domains = ", ".join(report.domains) or "Not recorded"
    scope_stages = ", ".join(_label(stage) for stage in report.scope.stages) or "Not recorded"
    scope_facts = "".join((
        _fact("Command platform", _label(report.scope.command_platform)),
        _fact("Included stages", scope_stages),
        _fact("Include pre-ATT&CK", report.scope.include_pre),
        _fact("Curated only", report.scope.curated_only),
        _fact("Network allowed", report.scope.allow_network),
        _fact("Administrator allowed", report.scope.allow_admin),
        _fact("High risk allowed", report.scope.allow_high_risk),
    ))
    engagement_facts = "".join((
        _fact("Actor STIX ID", report.actor_stix_id),
        _fact("Actor type", _label(report.actor_type) if report.actor_type else ""),
        _fact("Aliases", aliases),
        _fact("ATT&CK technique count", report.actor_technique_count),
        _fact("Domains", domains),
        _fact("Operator", report.operator),
        _fact("Target", report.target),
        _fact("Plan generated", report.generated),
        _fact("Observed execution start", report.execution_started_at),
        _fact("Observed execution completion", report.execution_completed_at),
    ))
    coverage_rows = (
        ("Catalog", f"{report.coverage.curated} curated · {report.coverage.fallback} fallback · "
                    f"{report.coverage.unsupported} unsupported"),
        ("Command outcomes", f"{report.coverage.outcome_passed} passed · {report.coverage.outcome_failed} failed · "
                             f"{report.coverage.outcome_skipped} skipped · {report.coverage.outcome_not_run} not run"),
        ("Detection outcomes", f"{report.coverage.detection_alerted} alerted · {report.coverage.detection_blocked} blocked · "
                               f"{report.coverage.detection_silent} silent · "
                               f"{report.coverage.detection_not_instrumented} not instrumented · "
                               f"{report.coverage.detection_not_assessed} not assessed"),
        ("Mappings", f"{report.coverage.expected_telemetry_mapped} expected telemetry · "
                     f"{report.coverage.attack_detection_mapped} ATT&CK detection · "
                     f"{report.coverage.sigma_mapped} Sigma"),
    )
    coverage_table = "".join(
        f"<tr><th>{_h(label)}</th><td>{_h(value)}</td></tr>" for label, value in coverage_rows
    )
    content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>AdversaryFlow engagement report · {_h(report.actor_name)}</title>
<style>
:root{{--ink:#132039;--muted:#60708d;--line:#dce3ee;--surface:#f5f7fb;--navy:#101b33;--blue:#376cf6;--cyan:#12a8b4;--green:#16865b;--amber:#b86d13;--red:#bd3346}}*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif;background:#fff}}main{{width:min(1120px,calc(100% - 48px));margin:0 auto;padding:56px 0 80px}}header{{position:relative;overflow:hidden;border-radius:22px;padding:42px;background:var(--navy);color:#fff;box-shadow:0 24px 70px #13203920}}header:after{{content:"";position:absolute;width:360px;height:360px;right:-170px;top:-220px;border:70px solid #376cf655;border-radius:50%}}.kicker{{color:#8eb6ff;font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}}h1{{max-width:800px;margin:10px 0 7px;font-size:38px;line-height:1.05;letter-spacing:-.04em}}header p{{max-width:760px;margin:0;color:#c8d3e8}}.meta{{display:flex;flex-wrap:wrap;gap:8px;margin:24px 0 0;padding:0;list-style:none}}.meta li,.badge{{border:1px solid #ffffff26;border-radius:999px;padding:5px 9px;font-size:11px}}.safety,.honesty{{margin:18px 0 0;border-left:3px solid #4f81ff;padding:12px 15px;background:#eef3ff;color:#31456c}}.honesty{{border-color:var(--amber);background:#fff8ee;color:#664318}}.metrics{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:24px 0}}.metric{{border:1px solid var(--line);border-radius:13px;padding:16px;background:#fff}}.metric strong{{display:block;font-size:25px}}.metric span{{color:var(--muted);font-size:11px}}h2{{margin:42px 0 12px;font-size:22px;letter-spacing:-.02em}}.overview-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}}.overview-grid>section{{border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--surface)}}.overview-grid h2{{margin:0 0 10px;font-size:16px}}.facts{{margin:0;padding-left:18px;color:var(--muted)}}.facts strong{{color:var(--ink)}}.gap-chips{{display:flex;flex-wrap:wrap;gap:8px;margin:0;padding:0;list-style:none}}.gap-chips li{{display:flex;gap:8px;border:1px solid #f0cfaa;border-radius:10px;padding:8px 11px;background:#fff8ee}}.gap-chips span{{color:#795126}}.technique-list{{display:grid;gap:12px}}.technique{{border:1px solid var(--line);border-radius:15px;padding:18px;background:#fff;page-break-inside:avoid}}.technique-head{{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}}.technique-head>div:first-child{{display:grid;grid-template-columns:auto 1fr;column-gap:9px}}.sequence{{grid-row:1/3;display:grid;place-items:center;width:33px;height:33px;border-radius:8px;background:#edf2ff;color:var(--blue);font-weight:800}}h3{{margin:0;font-size:15px}}h3 a{{color:var(--blue)}}.technique-head p{{margin:2px 0 0;color:var(--muted);font-size:11px}}.badges{{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:5px}}.badge{{border-color:var(--line);padding:3px 7px;background:var(--surface);color:var(--muted);font-weight:700;text-transform:capitalize}}.curated,.outcome-passed,.detection-alerted{{color:var(--green);background:#edf9f4;border-color:#b8e6d3}}.fallback,.outcome-skipped,.detection-not_assessed{{color:var(--amber);background:#fff8ee;border-color:#f0cfaa}}.outcome-failed,.detection-silent{{color:var(--red);background:#fff1f3;border-color:#f2c1ca}}.technique-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:14px}}.technique-grid section{{border-radius:10px;padding:12px;background:var(--surface)}}h4{{margin:0 0 5px;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}}.technique-grid p{{margin:0 0 7px;font-size:12px}}.limitation{{color:#795126}}small{{color:var(--muted)}}table{{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;border:1px solid var(--line);border-radius:14px}}th,td{{padding:11px 13px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}th{{background:var(--surface);color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.08em}}tr:last-child td{{border-bottom:0}}.coverage-table th{{width:180px}}.gap-category{{color:var(--amber);font-weight:700}}footer{{margin-top:44px;border-top:1px solid var(--line);padding-top:15px;color:var(--muted);font-size:10px}}code{{font-family:Consolas,monospace;overflow-wrap:anywhere}}.empty{{color:var(--muted)}}@media(max-width:850px){{.metrics{{grid-template-columns:repeat(3,1fr)}}.technique-grid,.overview-grid{{grid-template-columns:1fr}}}}@media(max-width:560px){{main{{width:min(100% - 24px,1120px);padding-top:12px}}header{{padding:26px}}h1{{font-size:29px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.technique-head{{display:block}}.badges{{justify-content:flex-start;margin-top:10px}}}}@media print{{main{{width:100%;padding:0}}header{{box-shadow:none}}.technique{{break-inside:avoid}}}}
</style></head><body><main>
<header><div class="kicker">AdversaryFlow · Purple-team engagement report</div><h1>{_h(report.actor_name)} <small>({_h(report.actor_id)})</small></h1><p>Authorized adversary-emulation coverage and detection validation for a disposable lab.</p><ul class="meta"><li>{_h(report.platform.title())}</li><li>Operator: {_h(report.operator or 'Not recorded')}</li><li>Target: {_h(report.target or 'Not recorded')}</li><li>Plan: {_h(report.generated)}</li></ul></header>
<p class="safety"><strong>Planner boundary:</strong> AdversaryFlow generated this report from a catalog-rebound plan. The service did not execute commands, connect to a target, or include runnable commands in this report.</p>
<p class="honesty"><strong>Evidence limitation:</strong> A verified receipt confirms the integrity of a self-reported lab record; it is not independent proof of execution or detection. Correlate run IDs, timestamps, and hashes with SIEM or endpoint telemetry.</p>
{description}<section class="metrics">{card_html}</section>
<div class="overview-grid"><section><h2>Engagement metadata</h2><ul class="facts">{engagement_facts}</ul></section><section><h2>Authorized scope</h2><ul class="facts">{scope_facts}</ul></section></div>
<section><h2>Coverage breakdown</h2><table class="coverage-table"><tbody>{coverage_table}</tbody></table></section>
<section><h2>Coverage gap summary</h2><ul class="gap-chips">{gap_chips}</ul></section>
<section><h2>Technique results</h2><div class="technique-list">{''.join(rows)}</div></section>
<section><h2>Coverage gaps and follow-up</h2><table><thead><tr><th>Category</th><th>Technique</th><th>Finding</th></tr></thead><tbody>{gap_rows}</tbody></table></section>
<footer>Plan generated {_h(report.report_generated)} · Schema {_h(report.schema_version)} · Tool {_h(report.tool_version)} · ATT&amp;CK data {_h(report.data_version)} · Plan SHA-256 <code>{_h(report.plan_sha256)}</code><br>Catalog Sigma references are included only when explicitly present in the catalog; absence is not a claim that no community rule exists.</footer>
</main></body></html>"""
    return content.encode("utf-8")


class _PdfLayout:
    width = 612.0
    height = 792.0
    left = 48.0
    right = 564.0
    bottom = 50.0

    def __init__(self, report: EngagementReport) -> None:
        self.report = report
        self.pages: List[List[str]] = []
        self.page: List[str] = []
        self.y = 0.0
        self._new_page()

    def _new_page(self) -> None:
        if self.page:
            self.pages.append(self.page)
        self.page = []
        self.y = 742.0
        self.rect(0, 762, self.width, 30, fill=(0.063, 0.106, 0.2))
        self.text(self.left, 775, "ADVERSARYFLOW / PURPLE-TEAM REPORT", 8, bold=True, color=(0.64, 0.75, 1.0))

    def finish(self) -> List[List[str]]:
        if self.page:
            self.pages.append(self.page)
            self.page = []
        for index, page in enumerate(self.pages, 1):
            page.append(_pdf_text_command(self.left, 28, "AUTHORIZED DISPOSABLE-LAB PLANNING ARTIFACT", 7, False, (0.38, 0.44, 0.55)))
            page.append(_pdf_text_command(518, 28, f"{index} / {len(self.pages)}", 7, True, (0.38, 0.44, 0.55)))
        return self.pages

    def ensure(self, height: float) -> None:
        if self.y - height < self.bottom:
            self._new_page()

    def text(self, x: float, y: float, value: str, size: float = 10, *, bold: bool = False,
             color: Tuple[float, float, float] = (0.075, 0.125, 0.225)) -> None:
        self.page.append(_pdf_text_command(x, y, value, size, bold, color))

    def rect(self, x: float, y: float, width: float, height: float, *, fill: Tuple[float, float, float],
             stroke: Tuple[float, float, float] | None = None) -> None:
        command = f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg "
        if stroke:
            command += f"{stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG 0.7 w {x:.2f} {y:.2f} {width:.2f} {height:.2f} re B"
        else:
            command += f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re f"
        self.page.append(command)

    def heading(self, value: str, *, size: float = 18) -> None:
        self.ensure(size + 20)
        self.text(self.left, self.y, value, size, bold=True)
        self.y -= size + 10

    def paragraph(self, value: str, *, size: float = 9, color: Tuple[float, float, float] = (0.26, 0.32, 0.43),
                  indent: float = 0, space_after: float = 8) -> None:
        width = self.right - self.left - indent
        lines = _wrap_pdf(value, size, width)
        line_height = size * 1.38
        for line in lines or [""]:
            self.ensure(line_height)
            self.text(self.left + indent, self.y, line, size, color=color)
            self.y -= line_height
        self.y -= space_after

    def rule(self) -> None:
        self.ensure(8)
        self.page.append(f"0.86 0.89 0.94 RG 0.6 w {self.left:.2f} {self.y:.2f} m {self.right:.2f} {self.y:.2f} l S")
        self.y -= 10


def _pdf_string(value: str) -> str:
    encoded = value.encode("cp1252", "replace").decode("latin-1")
    return encoded.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_text_command(x: float, y: float, value: str, size: float, bold: bool,
                      color: Tuple[float, float, float]) -> str:
    font = "F2" if bold else "F1"
    return (f"BT {color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg /{font} {size:.2f} Tf "
            f"1 0 0 1 {x:.2f} {y:.2f} Tm ({_pdf_string(value)}) Tj ET")


def _wrap_pdf(value: str, size: float, width: float) -> List[str]:
    plain = re.sub(r"\s+", " ", value).strip()
    if not plain:
        return []
    characters = max(12, int(width / (size * 0.53)))
    return textwrap.wrap(plain, width=characters, break_long_words=True, break_on_hyphens=True)


def _truncate(value: str, maximum: int) -> str:
    if len(value) <= maximum:
        return value
    return value[:maximum - 1].rstrip() + "…"


def _layout_pdf(report: EngagementReport) -> List[List[str]]:
    layout = _PdfLayout(report)
    layout.text(layout.left, layout.y, "PURPLE-TEAM ENGAGEMENT REPORT", 9, bold=True, color=(0.22, 0.42, 0.96))
    layout.y -= 27
    for line in _wrap_pdf(f"{report.actor_name} ({report.actor_id})", 25, layout.right - layout.left):
        layout.text(layout.left, layout.y, line, 25, bold=True)
        layout.y -= 31
    layout.paragraph("Authorized adversary-emulation coverage and detection validation for a disposable lab.", size=11)
    layout.rect(layout.left, layout.y - 54, layout.right - layout.left, 54, fill=(0.93, 0.95, 1.0), stroke=(0.74, 0.81, 0.96))
    layout.text(layout.left + 14, layout.y - 19, "PLANNER BOUNDARY", 8, bold=True, color=(0.22, 0.42, 0.96))
    layout.text(layout.left + 14, layout.y - 38, "No commands were executed, no target was contacted, and this report contains no runnable commands.", 9)
    layout.y -= 72
    metadata = [
        f"Platform: {_label(report.platform)}", f"Operator: {report.operator or 'Not recorded'}",
        f"Target: {report.target or 'Not recorded'}", f"Plan generated: {report.generated}",
        f"ATT&CK data: {report.data_version}",
    ]
    for value in metadata:
        layout.paragraph(value, size=9, space_after=2)
    layout.y -= 9
    layout.heading("Engagement overview")
    metrics = [
        ("Planned occurrences", len(report.techniques)), ("Unique techniques", report.unique_techniques),
        ("Recorded outcomes", report.recorded), ("Detection assessed", report.detection_assessed),
        ("Detection alerted", report.alerted), ("Open gap findings", len(report.gaps)),
    ]
    card_width = (layout.right - layout.left - 12) / 3
    for index, (label, metric_value) in enumerate(metrics):
        if index == 3:
            layout.y -= 64
        column = index % 3
        x = layout.left + column * (card_width + 6)
        layout.rect(x, layout.y - 51, card_width, 51, fill=(0.97, 0.98, 0.995), stroke=(0.86, 0.89, 0.94))
        layout.text(x + 12, layout.y - 22, str(metric_value), 17, bold=True)
        layout.text(x + 12, layout.y - 39, label, 7.5, color=(0.38, 0.44, 0.55))
    layout.y -= 76
    layout.heading("Coverage gap summary", size=15)
    summary = _gap_summary(report.gaps)
    if summary:
        for category, count in summary.items():
            layout.paragraph(f"- {category}: {count}", size=9, indent=6, space_after=3)
    else:
        layout.paragraph("No coverage gaps were identified from the recorded plan.")

    layout.y -= 8
    layout.heading("Technique results")
    for item in report.techniques:
        guidance = _truncate(item.detection_guidance, 320) or "No ATT&CK detection guidance mapped."
        sigma = "; ".join(
            f"{reference.label} ({reference.url})" for reference in item.sigma_references
        ) or "No catalog Sigma reference"
        sources = ", ".join(item.data_sources) or "Not mapped"
        expected = _truncate(item.expected_telemetry, 340) or "Not mapped"
        evidence = _truncate(item.evidence_notes, 220) or "No operator evidence note recorded."
        evidence_source = _label(item.evidence_source) if item.evidence_source else "Not recorded"
        telemetry_references = "; ".join(item.telemetry_references) or "Not recorded"
        title_lines = _wrap_pdf(f"{item.sequence:02d}  {item.technique_id} - {item.technique_name}", 11, layout.right - layout.left)
        status_lines = _wrap_pdf(
            f"{item.tactic_title} | {item.command_source} | outcome: {_label(item.outcome)} | detection: {_label(item.detection_result)}",
            8, layout.right - layout.left,
        )
        block_lines = (
            title_lines
            + status_lines
            + _wrap_pdf(f"Expected telemetry: {expected}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"ATT&CK data sources: {sources}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"Detection mapping: {guidance}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"Sigma: {sigma}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"Evidence: {evidence}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"Evidence source: {evidence_source}", 8.5, layout.right - layout.left - 12)
            + _wrap_pdf(f"Telemetry references: {telemetry_references}", 8.5, layout.right - layout.left - 12)
        )
        estimated = 20 + len(block_lines) * 12
        layout.ensure(min(estimated, 230))
        for line in title_lines:
            layout.text(layout.left, layout.y, line, 11, bold=True)
            layout.y -= 14
        for line in status_lines:
            layout.text(layout.left, layout.y, line, 8, bold=True, color=(0.22, 0.42, 0.96))
            layout.y -= 12
        layout.y -= 3
        for label, value in (
            ("Expected telemetry", expected), ("ATT&CK data sources", sources),
            ("Detection mapping", guidance), ("Sigma", sigma), ("Evidence", evidence),
            ("Evidence source", evidence_source), ("Telemetry references", telemetry_references),
        ):
            layout.paragraph(f"{label}: {value}", size=8.5, indent=8, space_after=2)
        layout.rule()

    layout.heading("Coverage gaps and follow-up")
    if not report.gaps:
        layout.paragraph("No coverage gaps were identified from the recorded plan.")
    for index, gap in enumerate(report.gaps):
        remaining = len(report.gaps) - index
        if remaining <= 2 and layout.y < 180:
            layout._new_page()
        gap_title = _wrap_pdf(f"{gap.category} - {gap.technique_id} - {gap.technique_name}", 9, layout.right - layout.left)
        layout.ensure(30 + len(gap_title) * 12)
        for line in gap_title:
            layout.text(layout.left, layout.y, line, 9, bold=True, color=(0.72, 0.42, 0.08))
            layout.y -= 12
        layout.y -= 2
        layout.paragraph(gap.detail, size=8.5, indent=8, space_after=5)
    layout.ensure(65)
    layout.rule()
    layout.paragraph(f"Report generated: {report.report_generated}", size=7.5, space_after=1)
    layout.paragraph(f"Plan SHA-256: {report.plan_sha256}", size=7.5, space_after=1)
    layout.paragraph("Catalog Sigma references are included only when explicitly present; absence is not a claim that no community rule exists.", size=7.5)
    return layout.finish()


@dataclass(frozen=True)
class _HtmlBlock:
    kind: str
    text: str


class _ReportHtmlParser(HTMLParser):
    """Extract the visible report blocks used by the dependency-free PDF writer."""

    _block_tags: ClassVar[frozenset[str]] = frozenset(
        {"h1", "h2", "h3", "h4", "p", "li", "small", "th", "td", "footer"}
    )
    _skipped_tags: ClassVar[frozenset[str]] = frozenset({"head", "script", "style"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: List[_HtmlBlock] = []
        self._capture_tag: str | None = None
        self._parts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        del attrs
        if tag in self._skipped_tags:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "br" and self._capture_tag:
            self._parts.append(" ")
        elif tag in self._block_tags and self._capture_tag is None:
            self._capture_tag = tag
            self._parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag in self._skipped_tags:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth or tag != self._capture_tag:
            return
        value = re.sub(r"\s+", " ", " ".join(self._parts)).strip()
        if value:
            self.blocks.append(_HtmlBlock(tag, value))
        self._capture_tag = None
        self._parts = []

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and self._capture_tag:
            self._parts.append(data)


def _layout_pdf_html(report: EngagementReport, document: bytes) -> List[List[str]]:
    parser = _ReportHtmlParser()
    try:
        parser.feed(document.decode("utf-8"))
        parser.close()
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReportError("The HTML report could not be rendered as PDF") from exc
    if not parser.blocks:
        raise ReportError("The HTML report did not contain printable content")

    layout = _PdfLayout(report)
    for block in parser.blocks:
        if block.kind == "h1":
            layout.heading(block.text, size=23)
        elif block.kind == "h2":
            layout.y -= 5
            layout.heading(block.text, size=15)
        elif block.kind == "h3":
            layout.heading(block.text, size=11)
        elif block.kind == "h4":
            layout.ensure(16)
            layout.text(layout.left, layout.y, block.text.upper(), 8, bold=True, color=(0.22, 0.42, 0.96))
            layout.y -= 13
        elif block.kind == "th":
            layout.paragraph(block.text.upper(), size=8, color=(0.22, 0.42, 0.96), space_after=2)
        elif block.kind == "td":
            layout.paragraph(block.text, size=8.5, indent=7, space_after=4)
        elif block.kind == "li":
            layout.paragraph(f"- {block.text}", size=8.5, indent=5, space_after=2)
        elif block.kind in {"small", "footer"}:
            layout.paragraph(block.text, size=7.5, color=(0.38, 0.44, 0.55), space_after=4)
        else:
            layout.paragraph(block.text, size=9, space_after=7)
    return layout.finish()


def _pdf_document(pages: Sequence[Sequence[str]]) -> bytes:
    objects: Dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
    }
    page_ids = []
    next_id = 5
    for commands in pages:
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        page_ids.append(page_id)
        stream = "\n".join(commands).encode("latin-1")
        objects[content_id] = b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[2] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("ascii")
    output = io.BytesIO()
    output.write(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0] * (max(objects) + 1)
    for object_id in range(1, max(objects) + 1):
        offsets[object_id] = output.tell()
        output.write(f"{object_id} 0 obj\n".encode("ascii"))
        output.write(objects[object_id])
        output.write(b"\nendobj\n")
    xref = output.tell()
    output.write(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return output.getvalue()


def render_pdf(report: EngagementReport) -> bytes:
    """Render the self-contained HTML report into a deterministic PDF."""
    html_document = render_html(report)
    return _pdf_document(_layout_pdf_html(report, html_document))
