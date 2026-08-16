# Implementation roadmap

## Completed MVP: safe local campaign lifecycle

The current release provides RoE validation, deterministic offline drafting, an optional OpenAI-compatible planning adapter, immutable reviewed drafts, explicit approval, fixed local synthetic and read-only behavioral execution, a commit-pinned local IDPT collection integration, telemetry-gap reporting, diagnostics, and a loopback-only review manager. No adapter accepts arbitrary commands or remote-target execution.

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

**Status: implemented for offline exports.**

- Normalize generic, Sentinel, Defender, Splunk, Elastic, and CrowdStrike offline exports and export gap findings as JSON/CSV.
- Correlate by run, host, ability, time window, user, and process context, with an explicit ambiguous state and read-only sensor preflight.
- Keep imports and validation offline; no connector may query or modify a production target.
- Acceptance: exports reproduce the campaign report counts and contain no secrets or raw provider content.

## Slice 4: catalog governance and retest workflow

**Status: catalog versioning, lifecycle validation, and signed release inventory implemented; retest workflow implemented.**

- Guided immutable retest drafts are derived from recorded detection gaps and retain source campaign/run provenance.
- Catalogs carry active semantic versions and lifecycle metadata; release builds emit `catalog-manifest.json`, covered by the signed SHA-256 manifest when GPG signing is enabled.
- Preserve the existing integrity check: changed RoE, catalog, or draft requires a new approval.
- Acceptance: a retest is traceable to a gap while execution remains fixed, local, and explicitly approved.

## Non-goals

AdversaryFlow will not add arbitrary command execution, exploit payload generation, credential theft, persistence, evasion, lateral movement, unrestricted networking, or remote-target execution.
