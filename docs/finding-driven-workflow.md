# Finding-driven workflow engine

`adversaryflow.finding_workflow` provides the stateful workflow layer for a guided product. It is independent of the local-synthetic adapter: an adapter, telemetry importer, user, or agent can all submit the same `Finding` object and receive the same gates and recommendations.

## Architecture and data model

The engine has four boundaries:

1. **Producers** create findings from observations, imported evidence, user input, or adapter results.
2. **`FindingWorkflowEngine`** validates commands, correlates findings, recalculates priority, applies gates, and emits recommendations.
3. **`WorkflowState`** is the resumable aggregate: phase, completed steps, findings, pending actions, decisions, audit entries, progress, status, metadata, and revision.
4. **Product adapters** render recommendations in the terminal, manager UI, API, or agent loop and call the same command methods.

`Finding` is first-class and contains identity, description, category, source, severity, confidence, calculated priority, evidence, tags, related findings, linked steps, status, timestamps, and lifecycle history. Its lifecycle is validated: `open -> validated -> exploited/mitigated -> closed`, with explicit rejection and revalidation paths where appropriate.

The JSON representation is intentionally plain and version-friendly. Sets are serialized as sorted lists, and persistence uses a temporary file followed by an atomic replace. `FindingWorkflowEngine.resume()` reconstructs the aggregate and recalculates derived state.

## Guided lifecycle

The default graph is:

`scope -> authorize -> discover -> validate -> assess -> mitigate -> verify -> report -> close`

Each step has dependencies, an explanation, optional required/blocked finding tags, and an action identifier. A step cannot be completed until dependencies and finding gates pass. Closure additionally requires zero open findings, which prevents a false “finished” state.

At every mutation the engine updates progress, phase, pending action IDs, and the audit log. Open findings produce validation or remediation recommendations; high and critical findings are mandatory. The UI can show `Recommendation.title` and `.explanation`, while an automated agent can execute `.action_id` through an allowlisted command handler.

## Branching and prioritization rules

* Findings correlate when they share a tag and category; each side records the other’s ID.
* Priority is `severity_score * confidence * urgency * exposure`, with severity scores of 0/10/30/60/100 for info through critical.
* Open findings recommend validation. Validated or exploited findings recommend mandatory mitigation. Closed/rejected findings do not block closure.
* Custom graphs can add dependencies and finding-tag gates. Duplicate step IDs, unknown dependencies, and dependency cycles fail during engine construction.
* Decisions are append-only records with actor, timestamp, choice, and notes, so a user override remains visible and auditable rather than silently changing state.

## Integration sketch

```python
from adversaryflow.workflow import Finding, FindingWorkflowEngine

engine = FindingWorkflowEngine(persistence_path="artifacts/workflow/state.json")
engine.complete_step("scope", actor="operator")
finding = engine.ingest_finding({
    "title": "Detection gap",
    "description": "Expected signal was not observed",
    "severity": "high",
    "category": "telemetry",
    "tags": {"T1059", "gap"},
})
next_actions = engine.recommendations()
engine.update_finding(finding.finding_id, status="validated", evidence={"event_id": "local-1"})
```

For a UI, serialize `engine.state.as_dict()` and `recommendations()` into the view model. For an agent, expose only `ingest_finding`, `update_finding`, `complete_step`, and `query_findings` as tools, and require the agent to present mandatory recommendations before continuing. For a report, include `state.findings`, `state.decisions`, and `state.audit_log`; this preserves evidence-to-decision traceability.

## Completeness and edge cases

Empty state starts at scope and has a valid next action. User-injected findings follow exactly the same validation and scoring rules as system findings. Unknown IDs, duplicate finding IDs, malformed confidence, invalid lifecycle transitions, blocked steps, cyclic graphs, and premature closure fail closed with actionable errors. Resuming a missing/corrupt persistence file raises the underlying read/parse error for the product’s recovery surface to report. Revisioned audit entries support optimistic concurrency checks in a higher-level repository without changing the core model.
