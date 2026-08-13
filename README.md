# AdversaryFlow

AdversaryFlow is a safety-first purple-team platform for turning current threat-intelligence into reviewable, scoped, defensive campaign simulations.

## MVP

The first vertical slice provides:

- A machine-readable Rules of Engagement (RoE) file.
- Hard target allowlist enforcement and denylist support.
- Mandatory dry-run planning.
- Human approval records for campaign execution.
- Audit events with redacted inputs and SHA-256 evidence references.
- MITRE ATT&CK STIX ingestion from the official public repository.
- Campaign plans that pair each technique with expected telemetry and validation questions.
- A provider-neutral AI review prompt that keeps planning defensive and novice-friendly.
- Versioned, safe emulation abilities with telemetry expectations, cleanup contracts, and deterministic plan hashes.

The MVP deliberately does not generate exploit payloads, persistence, credential theft, evasion, lateral movement commands, or unrestricted network actions. Execution adapters are simulation-only and must be extended behind the safety interfaces.

AI provider integration is intentionally left behind a small adapter boundary so an organization can choose its approved model, data-handling policy, and retention settings.

The `draft` command uses a deterministic offline fallback. A hosted or local model can implement the `AIPlanner` interface, receive `build_ai_request_prompt(...)`, return `AICampaignDraft`, and then pass through `validate_ai_draft(...)` before any emulation plan is created.

## IDPT-inspired capabilities

AdversaryFlow adopts the reference project's useful control-plane patterns: immutable ability metadata, fixed scenario planning, explicit technique and platform fields, telemetry as a first-class output, cleanup contracts, run-root evidence, and deterministic plan provenance. The initial catalog only permits abstract simulation actions, no arbitrary commands, no remote execution, and no non-loopback network scope.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m adversaryflow validate examples\roe.yaml
python -m adversaryflow plan --roe examples\roe.yaml --actor "APT29" --technique T1059.001
python -m adversaryflow draft --roe examples\roe.yaml --actor "APT29" --objective "validate endpoint process visibility"
```

Use `--live` only in a future approved adapter; the current release always produces a dry-run plan.

## Product direction

The intended workflow is: source-backed intelligence → novice-friendly campaign plan → manager review → scoped simulation → telemetry capture → gap report and retest plan.
