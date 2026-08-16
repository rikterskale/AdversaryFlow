# Schemas and artifact contracts

This page names the versioned formats emitted or consumed by the repository. The identifiers below are defined in source or packaged resources; they are not general interchange standards.

## Versioned schemas

| Identifier | Source or output | Documentation boundary |
|---|---|---|
| `ADVERSARYFLOW-ABILITY-CATALOG-1` | Ability catalog | Fixed ability metadata; commands are code-owned. |
| `ADVERSARYFLOW-CATALOG-MANIFEST-1` | Release `catalog-manifest.json` | Signed release inventory of active catalog versions, ability IDs, and SHA-256 hashes. |
| `ADVERSARYFLOW-ACTOR-PROFILES-1` | Actor-profile `profiles.json` | Profiles reference registered benign fixtures and procedures. |
| `ADVERSARYFLOW-ADAPTER-1` | Adapter preflight result | Built-in adapter contract version. |
| `ADVERSARYFLOW-BENIGN-PROCEDURES-1` | Benign-procedure catalog | Fixed local procedures and cleanup contracts. |
| `ADVERSARYFLOW-CAPABILITIES-1` | `capabilities` command output | Advertised capability metadata. |
| `ADVERSARYFLOW-COVERAGE-DASHBOARD-1` | `coverage` command and manager dashboard | Read-only actor, technique, detection, gap, and retest summary. |
| `ADVERSARYFLOW-COVERAGE-TRENDS-1` | `coverage trends` command | Read-only historical campaign, detection, and gap trend points. |
| `ADVERSARYFLOW-CTID-FIXTURES-1` | Packaged CTID fixture catalog | Synthetic fixture vocabulary; not production telemetry. |
| `ADVERSARYFLOW-DETECTION-MAPPINGS-1` | Detection export bundle | Defensive validation-template metadata. |
| `ADVERSARYFLOW-DETECTION-RULES-1` | `detection import` output | Offline imported rule inventory; no vendor deployment. |
| `ADVERSARYFLOW-DETECTION-SCORE-1` | `detection score` output | Read-only local evidence match scoring for imported rules. |
| `ADVERSARYFLOW-DETECTION-RULE-REGISTRY-1` | Packaged detection mapping registry | Code-owned rule-template mappings. |
| `ADVERSARYFLOW-EMULATION-1` | Emulation catalog output | Fixed local simulation ability set. |
| `ADVERSARYFLOW-IDPT-1` | IDPT integration provenance | Verified boundary between AdversaryFlow and the reviewed local IDPT checkout. |
| `ADVERSARYFLOW-IDPT-SCENARIOS-1` | IDPT scenario registry | Reviewed scenario-to-ability-set mappings. |
| `ADVERSARYFLOW-PLANNED-SENSOR-PREFLIGHT-1` | Pre-execution sensor snapshot assessment | Read-only validation of a supplied health manifest. |
| `ADVERSARYFLOW-RETEST-1` | `retest.json` | Immutable provenance from a source campaign and detection gaps. |
| `ADVERSARYFLOW-SENSOR-PREFLIGHT-1` | Post-run telemetry preflight | Read-only validation of normalized telemetry coverage. |
| `ADVERSARYFLOW-TELEMETRY-1` | Normalized telemetry JSONL | Offline vendor-export normalization and correlation input. |
| `ADVERSARYFLOW-RELEASE-MANIFEST-1` | `SHA256SUMS.json` | Release artifact names, sizes, and SHA-256 hashes. |
| `ADVERSARYFLOW-RETENTION-1` | `retention preview` output | Local retention eligibility preview; cleanup requires explicit confirmation. |

## Campaign and support artifacts

Campaign drafts use `draft.json` and `metadata.json`. Decisions use `approval.json`, `rejection.json`, or `cancellation.json`. Completed campaigns add `campaign-report.md` and `campaign-report.html`; runs add `progress.json`, `events.jsonl`, `manifest.json`, `audit.jsonl`, and `telemetry-gap-report.json`.

Support bundles are ZIP files containing exactly `diagnostics.json` and `README.txt`. The diagnostics include product, Python, platform, and doctor output; credentials and provider secrets are not included.

Manager-only workflows additionally write actor-profile `profiles.json`, benign-procedure `events.jsonl` and `manifest.json`, CTID-fixture `fixtures.jsonl`, `manifest.json`, `ctid-detection-gap-report.json`, and `training-timeline.md`, and executive-summary Markdown/PDF files beneath `artifacts/exports`.

Additional generated files are `sensor-preflight.json` for a campaign's supplied sensor-health snapshot, `benign-procedure-gap-report.json` and `cleanup.json` for benign-procedure assessment and cleanup, `rules.json` for an offline imported detection-rule registry, `kill-switch.json` for the local approval safety state, and `integration.json` for the IDPT integration record. Release output additionally includes `adversaryflow-source.zip`, `catalog-manifest.json`, and `sbom.cdx.json` alongside the release manifest. When `ADVERSARYFLOW_RELEASE_GPG_KEY` is configured, the catalog manifest is covered by the signed `SHA256SUMS.json` release manifest.

## Fixed serialized path names

The source also resolves these fixed serialized inputs and workflow files. The
names are listed exactly so changes to packaged resources or integration
boundaries cannot become undocumented:

| Area | Exact names |
|---|---|
| Packaged resources | `catalog.json`, `benign_procedures.json`, `capabilities.json`, `ctid_apt29_identity_fixtures.json`, `curated-linux.json`, `curated-macos.json`, `curated-windows.json`, `detection_mappings.json`, `idpt-windows-collection.json`, `idpt_scenarios.json`, `roe.yaml` |
| Enrichment outputs | `catalog.json`, `benign_procedures.json`, `coverage.json`, `emulation-plan.json` |
| Provider and manager state | `history.json`, `policy.json`, `profiles.json`, `detection-mappings.json` |
| IDPT integration boundary | `hosts.json`, `plan.json`, `roe.json`, `run.json`, `evidence-manifest.json` |
| Packaged manager asset | `manager.html` |

See [CLI_REFERENCE.md](CLI_REFERENCE.md), [DETECTION_VALIDATION.md](DETECTION_VALIDATION.md), [IDPT_INTEGRATION.md](IDPT_INTEGRATION.md), and [modules/local-manager.md](modules/local-manager.md) for operation-specific use.
