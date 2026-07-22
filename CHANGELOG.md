# Changelog

## Unreleased

- Load project `.env` files automatically while preserving exported environment variables.
- Add `doctor`, `validate-request`, and `--version` CLI paths for safer first-run setup.
- Report actionable JSON, schema, and missing-credential errors before external calls.
- Streamline the README quick start and add troubleshooting guidance.
- Add an interactive `init` wizard, JSON Schema export, and a tabletop template.
- Add safe, self-contained HTML reports with automatic format inference.
- Add optional authenticated service-connectivity checks to `doctor`.
- Add versioned immutable run bundles with hashed request, scenario, trace, and report artifacts.
- Add content-addressed source caching with URL freshness indexes and per-source trace provenance.
- Add schema-, prompt-, input-, and provider-aware model-node caching.
- Add forward-only store migrations plus cache inspection, selective clearing, and refresh controls.

## 0.3.0 — 2026-07-22

- Added `tasks.py`, a stdlib-only cross-platform developer task runner (`setup`, `test`, `lint`, `format`, `check`, `demo`, `clean`) that works identically on Windows, Linux, and macOS with no manual virtual-environment activation.
- Added one-command bootstrap helpers in `scripts/` for both shells (`setup.ps1`/`setup.sh`, `demo.ps1`/`demo.sh`).
- Reworked the Makefile into a thin wrapper that forwards to `tasks.py`, so `make` and `python tasks.py` share one implementation.
- Extended CI to a Windows + Linux matrix on Python 3.11 and 3.12, and added a demo smoke test to the pipeline.
- Rewrote the README and CONTRIBUTING setup instructions with copy-paste-safe Windows (PowerShell) and Linux/macOS command variants and a documented requirements section.
- Added `.gitattributes` line-ending rules so `.sh` stays LF and `.ps1`/`.bat` stay CRLF across platforms.

## 0.2.1 — 2026-07-14

- Renamed the project branding, Python package, CLI, Docker entrypoint, environment-variable prefix, user agents, documentation, tests, and repository assets to AdversaryFlow.
- Added GitHub-ready contribution, security, pull-request, issue, and publishing guidance.
- Added an example environment file and tightened repository ignore rules for generated and local-only artifacts.
- Regenerated and revalidated the deterministic APT29 demonstration artifacts under the AdversaryFlow namespace.

## 0.2.0 — 2026-07-14

- Added a production Brave Web Search adapter with query-time domain constraints and post-result allowlist enforcement.
- Added redirect-by-redirect URL validation, public-IP checks, content-type capture, response limits, and content hashing.
- Added source extraction and deterministic chunking for HTML, text, JSON/XML-like content, and PDFs.
- Added claim, excerpt, citation-source, citation-edge, and citation-graph models.
- Added strict structured response schemas for all 12 orchestration nodes.
- Added bounded retry and schema-repair logic with attempt-level traces.
- Added deterministic final factuality evaluation for claims, dossier techniques, and selected-path techniques.
- Added factuality score, citation coverage, repair count, and unsupported-claim reporting.
- Updated the CLI for Brave/null search selection and production policy configuration.
- Expanded the Markdown report and trace output.
- Expanded automated coverage from 6 to 12 tests.

## 0.1.0 — 2026-07-14

- Added typed request, dossier, procedure, source, and QA contracts.
- Added a twelve-call asynchronous orchestration DAG.
- Added cached philosophy and operational-constraint prompt layers.
- Added a local Enterprise ATT&CK STIX reader.
- Added allowlist and SSRF-resistant URL validation.
- Added deterministic request and output safety gates.
- Added a provider-neutral LLM interface and OpenAI-compatible adapter.
- Added deterministic demo mode, Markdown rendering, tests, Dockerfile, and CI.
