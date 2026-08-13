# Implementation roadmap

## Completed MVP: safe local campaign lifecycle

The current release provides RoE validation, deterministic offline drafting, an optional OpenAI-compatible planning adapter, immutable reviewed drafts, explicit approval, local-synthetic-only emulation, telemetry-gap reporting, diagnostics, and a loopback-only review manager. No slice expands execution beyond the fixed local-synthetic adapter.

## Slice 1: provider-adapter operational verification

**Status: implemented; requires an organization-owned endpoint smoke test.**

- OpenAI-compatible configuration is HTTPS-only and credentials remain process-environment values.
- `provider test` sends one planning request, then validates the returned draft against the selected RoE and ability catalog.
- A failed request or invalid draft creates no campaign; `campaign --fallback-offline` remains the safe rehearsal path.
- Release evidence: configuration validation, one approved non-production smoke test, and confirmation that no credential or raw response was persisted.

## Slice 2: governed provider profiles and provenance

**Status: implemented.**

- A profile-policy file allowlists approved provider endpoints and models.
- Campaign metadata records the selected profile name and policy version, without recording credentials, prompts, or responses.
- `doctor` and the loopback manager expose a read-only provider readiness report.
- An unapproved endpoint/model is rejected before any provider request, and provenance remains redacted.

## Slice 3: detection-validation export

**Status: planned.**

- Export normalized, synthetic-only telemetry expectations and gap findings as JSON/CSV for defensive tooling.
- Keep imports and validation offline; no connector may query or modify a production target.
- Acceptance: exports reproduce the campaign report counts and contain no secrets or raw provider content.

## Slice 4: catalog governance and retest workflow

**Status: planned.**

- Add signed/versioned catalog releases, deprecation metadata, and a guided retest draft derived from a recorded detection gap.
- Preserve the existing integrity check: changed RoE, catalog, or draft requires a new approval.
- Acceptance: a retest is traceable to a gap while execution remains local synthetic and explicitly approved.

## Non-goals

AdversaryFlow will not add arbitrary command execution, exploit payload generation, credential theft, persistence, evasion, lateral movement, unrestricted networking, or remote-target execution.
