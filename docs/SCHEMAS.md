# Schemas and artifact contracts

This page names the versioned formats emitted or consumed by the repository. The identifiers below are defined in source or packaged resources; they are not general interchange standards.

## Versioned schemas

| Identifier | Source or output | Documentation boundary |
|---|---|---|
| `ADVERSARYFLOW-ABILITY-CATALOG-1` | Ability catalog | Fixed ability metadata; commands are code-owned. |
| `ADVERSARYFLOW-ACTOR-PROFILES-1` | Actor-profile `profiles.json` | Profiles reference registered benign fixtures and procedures. |
| `ADVERSARYFLOW-ADAPTER-1` | Adapter preflight result | Built-in adapter contract version. |
| `ADVERSARYFLOW-BENIGN-PROCEDURES-1` | Benign-procedure catalog | Fixed local procedures and cleanup contracts. |
| `ADVERSARYFLOW-CAPABILITIES-1` | `capabilities` command output | Advertised capability metadata. |
| `ADVERSARYFLOW-COVERAGE-DASHBOARD-1` | `coverage` command and manager dashboard | Read-only actor, technique, detection, gap, and retest summary. |
| `ADVERSARYFLOW-CTID-FIXTURES-1` | Packaged CTID fixture catalog | Synthetic fixture vocabulary; not production telemetry. |
| `ADVERSARYFLOW-DETECTION-MAPPINGS-1` | Detection export bundle | Defensive validation-template metadata. |
| `ADVERSARYFLOW-DETECTION-RULE-REGISTRY-1` | Packaged detection mapping registry | Code-owned rule-template mappings. |
| `ADVERSARYFLOW-EMULATION-1` | Emulation catalog output | Fixed local simulation ability set. |
| `ADVERSARYFLOW-IDPT-1` | IDPT integration provenance | Verified boundary between AdversaryFlow and the reviewed local IDPT checkout. |
| `ADVERSARYFLOW-IDPT-SCENARIOS-1` | IDPT scenario registry | Reviewed scenario-to-ability-set mappings. |
| `ADVERSARYFLOW-PLANNED-SENSOR-PREFLIGHT-1` | Pre-execution sensor snapshot assessment | Read-only validation of a supplied health manifest. |
| `ADVERSARYFLOW-RETEST-1` | `retest.json` | Immutable provenance from a source campaign and detection gaps. |
| `ADVERSARYFLOW-SENSOR-PREFLIGHT-1` | Post-run telemetry preflight | Read-only validation of normalized telemetry coverage. |
| `ADVERSARYFLOW-TELEMETRY-1` | Normalized telemetry JSONL | Offline vendor-export normalization and correlation input. |
| `ADVERSARYFLOW-RELEASE-MANIFEST-1` | `SHA256SUMS.json` | Release artifact names, sizes, and SHA-256 hashes. |

## Campaign and support artifacts

Campaign drafts use `draft.json` and `metadata.json`. Decisions use `approval.json`, `rejection.json`, or `cancellation.json`. Completed campaigns add `campaign-report.md` and `campaign-report.html`; runs add `progress.json`, `events.jsonl`, `manifest.json`, `audit.jsonl`, and `telemetry-gap-report.json`.

Support bundles are ZIP files containing exactly `diagnostics.json` and `README.txt`. The diagnostics include product, Python, platform, and doctor output; credentials and provider secrets are not included.

Manager-only workflows additionally write actor-profile `profiles.json`, benign-procedure `events.jsonl` and `manifest.json`, CTID-fixture `fixtures.jsonl`, `manifest.json`, `ctid-detection-gap-report.json`, and `training-timeline.md`, and executive-summary Markdown/PDF files beneath `artifacts/exports`.

See [CLI_REFERENCE.md](CLI_REFERENCE.md), [DETECTION_VALIDATION.md](DETECTION_VALIDATION.md), [IDPT_INTEGRATION.md](IDPT_INTEGRATION.md), and [modules/local-manager.md](modules/local-manager.md) for operation-specific use.
