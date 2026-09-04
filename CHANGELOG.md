# Changelog

All notable changes to AdversaryFlow are documented here.

## 0.3.0 — 2026-09-04

- Replaced 146 generic temporary-file proxies with explicit, bounded,
  technique-relevant exercises across 25 scenario families, each with a
  digest-protected self-reported execution receipt.
- Added run IDs, start/completion timestamps, exit codes, stdout/stderr hashes,
  receipt verification, and endpoint/SIEM references to execution evidence.
- Made exported runbooks review-only by commenting every command, and added a
  native Windows CI job that executes both PowerShell launchers.
- Added structured command risk, privilege, network, telemetry, prerequisite,
  timeout, rollback, and cleanup metadata with explicit high-risk acknowledgment.
- Added passed/failed/skipped evidence records, operator/target context, cleanup
  verification, schema 2.0 exports, and safe JSON plan resume.
- Made first-run ATT&CK bootstrap asynchronous with progress and retry UX.
- Added bounded, validated, atomic, provenance-recorded cache downloads plus
  refresh serialization, rate limits, consistency resets, and repair commands.
- Added CSRF protection, remote-bind opt-in, security headers, request IDs,
  structured logs, diagnostics, and strict domain validation.
- Added cross-platform CI/package smoke tests, CodeQL, pinned actions, SBOMs,
  checksums, provenance attestations, and optional PyPI trusted publishing.
- Added Apache-2.0 licensing, security policy, NOTICE, and expanded operations,
  installation, export, and release guidance.

## 0.2.0 — 2026-09-04

- Added exact-platform command selection and explicit unsupported states.
- Corrected multi-domain ATT&CK indexing and wired domain selection into the UI.
- Added readiness/error contracts, versioned run state, and schema-versioned exports.
- Repositioned public copy and command contracts for disposable development labs.
- Renamed workflow/export fields to `commands`, `command_source`, and `command`.
- Added Python packaging, pinned runtime dependencies, cross-platform launchers, tests, and CI.
- Improved keyboard, screen-reader, reduced-motion, and offline-font behavior.

## 0.1.0 — 2026-09-04

- Initial guided adversary-emulation planner.
