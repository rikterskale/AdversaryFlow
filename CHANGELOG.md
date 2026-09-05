# Changelog

All notable changes to AdversaryFlow are documented here.

## Unreleased

- Stopped install and release copy from treating PyPI as a coming install
  path. Distribution is a source checkout or a GitHub Release wheel.
- Removed the optional PyPI trusted-publishing steps from the release
  workflow.

## 0.4.0 — 2026-09-05

- Made first-run simpler: a recommended-actor start, in-app help, a visible
  setup-error banner with retry, actor-gallery pagination, and a platform
  hint when the browser OS differs from the selected lab OS. The plan now
  opens on the first runnable stage, lists copyable commands first, and
  keeps unsupported techniques below them.
- Reframed Scope around safe-by-default safety switches, collapsed expert
  plan options, and added copy/run/record coaching on the plan and export
  screens so a first-time operator can finish without reading the handbook.
- Added a skip-to-content link, replaced actor-card "TTPs" with
  "techniques", and surfaced popular actors as "Start here" chips.
- Aligned the OpenAPI command contract with the plan schema (`direct` /
  `lab_proxy` fidelity and `none` risk), made Windows `install.ps1` fail when
  `doctor` fails, and kept `/api/health` ready when a refresh fails but a
  previous ATT&CK index is still loaded.
- Hardened fallback command templating against braces in technique names,
  normalized unhandled API errors to `request_failed`, refused cross-origin
  mutating requests, and rejected non-ISO-8601 timestamps in native telemetry
  collection.
- Enabled macOS operator execution kits using a portable Bash runner
  (`sha256sum` or `shasum`, GNU or BSD `base64`).
- Treated every 127.0.0.0/8 and IPv6 loopback address as loopback, started
  Waitress with an explicit thread pool and channel timeout, and warned when
  `--api-token` is passed on the command line.
- Showed a domain-download loader when ICS or Mobile is first selected, and
  added a live-process liveness smoke test.

- Added a novice operator handbook (install, first verified PoC, everyday
  use, remediation, recovery, upgrades, and support escalation) with
  commands checked against the 0.3.0 CLI.
- Split command result from detection result on the plan screen, stopped
  evidence edits from rebuilding the whole stage, and added j/k/c keyboard
  controls plus a visible local-save chip.
- Showed catalog prerequisites, expected output, timeout, and rollback on each
  card, and moved ATT&CK description, data sources, and detection text behind
  an expandable context panel.
- Made install copy lead with the source launcher and a GitHub/wheel pipx
  path; `pipx install adversaryflow` is documented as unavailable until PyPI
  publication.
- Removed live SAM exports, account and service creation, session locks, IMDS
  queries, recursive credential greps, and third-party HTTP fetches from the
  catalog; remaining persistence tests keep explicit high-risk acknowledgement.
- Stopped per-request API failures from marking the whole service failed, and
  added GET /api/live for process liveness separate from ATT&CK readiness.
- Surfaced ATT&CK data sources and detection text on plan cards and in exports.
- Added acceptable-use and code-of-conduct documents, filled the Apache
  copyright line, and expanded MITRE attribution in NOTICE.
- Labelled every catalog command with an explicit fidelity class (`direct`,
  `bounded synthetic`, or `lab proxy`) and surfaced those badges on the plan.
- Rebound execution kits to the live catalog so client-supplied command text
  cannot be packaged as an official runner, and bundled a portable copy of the
  bounded-exercise runner when a plan includes those steps.
- Restored the last in-progress plan from this browser after reload, made JSON
  resume a real keyboard-accessible button, and replaced native confirm dialogs
  with an in-app risk acknowledgement that shows the command.
- Polished the responsive wizard with a compact mobile header, page-level
  overflow protection, clean ATT&CK descriptions, concise actor-card labels,
  visible search result counts, and less intrusive screen-reader focus.
- Replaced the browser-native remote token prompt with an accessible in-app
  connection dialog that keeps credentials scoped to the current tab.
- Hardened HTTP responses with no-store API caching, request-ID validation,
  clickjacking and opener isolation, a restrictive permissions policy, and
  tighter CSP directives.
- Added weekly Dependabot coverage for the npm-based browser toolchain.
- Added one-click, offline Windows and Linux execution kits containing an
  integrity-bound CSV and standalone PowerShell/Bash runner.
- Added per-step run/edit/skip/abort approval, mandatory edit reasons, separate
  cleanup approval, timeouts, stdout/stderr capture, and command/output hashes.
- Added portable HTML, Markdown, JSON, CSV, JSONL, and SHA-256 execution evidence
  generated entirely on the destination machine.
- Replaced 146 generic temporary-file proxies with explicit, bounded,
  technique-relevant exercises across 25 scenario families, each with a
  digest-protected self-reported execution receipt.
- Added read-only Windows, Linux, and macOS log collection, normalized endpoint/SIEM
  correlation, run-ID process markers, and explicit acceptance contracts for all
  146 bounded techniques.
- Added run IDs, start/completion timestamps, exit codes, stdout/stderr hashes,
  receipt verification, and endpoint/SIEM references to execution evidence.
- Made exported runbooks review-only by commenting every command, and added a
  native Windows CI job that executes both PowerShell launchers.
- Updated artifact upload, download, and build-provenance Actions to their
  current Node 24-based releases while retaining immutable SHA pins.

## 0.3.0 — 2026-09-04

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
