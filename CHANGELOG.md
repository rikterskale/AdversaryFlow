# Changelog

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
