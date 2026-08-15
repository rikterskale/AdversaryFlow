# Documentation gap analysis

## Audit method

This audit was performed against the repository contents on 2026-08-15. The checkout contains 131 tracked files: 130 UTF-8 text files (9,983 lines) and one tracked PNG binary asset, `docs/assets/campaign-guide.png`. The text files were read line by line and the PNG was inspected as a binary visual asset. The comparison uses source literals, parser construction, route dispatch, artifact writes, environment-variable reads, package metadata, workflow configuration, and test assertions. A statement is treated as verified only when the cited source or test supplies the evidence.

The audited implementation surface is 38 Python modules under `src/adversaryflow/`, the packaged HTML/CSS/JavaScript manager assets, 16 JSON resource/data files, the two installer scripts, `Dockerfile`, `pyproject.toml`, the workflow and release scripts, 27 Markdown documents, the example RoE, and 32 test modules. The source-derived inventory is: 37 parser identifiers (including nested parser names), 31 long options, 19 non-null parser defaults, 43 manager route forms, 8 environment-variable names, and 18 concrete serialized artifact filenames. These are extracted by `scripts/source_documentation_contract.py`; the check compares the literal inventories against the designated user documentation.

The existing ground-truth rule is explicit in `documentation_prompt.txt:5-13`: document only verified behavior, inspect parsers before documenting CLI behavior, and use a `[VERIFY: ...]` tag for unconfirmed details. Existing checks are `scripts/validate_documentation.py:24-69` and `scripts/documentation_gap_analysis.py:23-177`.

## Source-level comparison

### CLI parser

The parser is built with `argparse` in `src/adversaryflow/cli.py:88-245`. It defines these top-level commands: `validate`, `plan`, `intel-sync`, `draft`, `demo`, `doctor`, `support-bundle`, `capabilities`, `adapter`, `guide`, `provider`, `campaign`, `telemetry`, `detection`, `coverage`, and `manager`. Nested parser construction defines `adapter status`, provider status/validate/configure/diagnose/profile/policy/test, campaign lifecycle operations, telemetry normalize/preflight/export, and detection export (`cli.py:131-244`).

`docs/CLI_REFERENCE.md:7-73` documents the complete parser command and option surface. The source-derived contract now compares every `add_parser`, long `add_argument`, and non-null literal default against that reference. It passed after the artifact documentation correction.

The parser-to-behavior comparison is also direct: `cli.py:257-555` contains the dispatch and exit behavior. Tests cover CLI behavior in `tests/test_campaign_cli.py`, `tests/test_cli_coverage.py`, `tests/test_guide_cli.py`, `tests/test_doctor_support.py`, `tests/test_provider.py`, `tests/test_provider_client.py`, `tests/test_lifecycle.py`, and `tests/test_extended_features.py`.

### Manager routes

The HTTP dispatch is implemented in `src/adversaryflow/manager.py:488-600`; loopback binding is enforced at `manager.py:606-611`. The documented route tables at `docs/modules/local-manager.md:26-74` cover the GET resources, POST actions, dynamic campaign routes, actor-profile routes, query parameters, request confirmation strings, and write boundary. The source-derived contract checks the literal routes plus the dynamic route forms.

The browser asset is a packaged resource loaded by `manager.py:103`; the separate packaged HTML, CSS, and JavaScript are under `src/adversaryflow/resources/`. The checked-in walkthrough image was inspected and agrees with the documented review-before-approval flow; it is not executable behavior evidence.

### Environment variables

Provider reads are implemented in `src/adversaryflow/provider.py:114-137`; validation and HTTPS/key requirements are at `provider.py:158-179`. The provider guide documents `ADVERSARYFLOW_PROVIDER`, `ADVERSARYFLOW_MODEL`, `ADVERSARYFLOW_ENDPOINT`, `ADVERSARYFLOW_API_KEY`, `ADVERSARYFLOW_PROFILE`, and `ADVERSARYFLOW_PROFILE_FILE` at `docs/modules/providers.md:5-15`.

Other source reads are `ADVERSARYFLOW_IDPT_ROOT` in `src/adversaryflow/idpt.py:99-105` and `ADVERSARYFLOW_RELEASE_GPG_KEY` in `scripts/release.py:52`. They are documented in `docs/IDPT_INTEGRATION.md:11-25`, `docs/INSTALL.md:73`, and `docs/DEVELOPMENT.md:43`. `ADVERSARYFLOW_SYNTHETIC` is a serialized event marker in `src/adversaryflow/loopback.py:49`, not an environment variable, and is excluded from the environment-variable check for that source-backed reason.

### Serialized artifacts

Campaign draft and decision files are written by `src/adversaryflow/workflow.py:61-62`, `src/adversaryflow/campaign_service.py:23-25`, and `src/adversaryflow/lifecycle.py:57-79`. Run artifacts are written by `workflow.py:108-159` and reports by `src/adversaryflow/reports.py:39-43`. Support ZIP members are fixed in `src/adversaryflow/support.py:12-21`. Manager-only artifacts are written by `src/adversaryflow/benign_procedures.py:35-53`, `src/adversaryflow/ctid.py:33-46`, `src/adversaryflow/product_tools.py:66-68`, and `src/adversaryflow/idpt.py:161-262`.

Before this audit, `docs/SCHEMAS.md:27-33` omitted six concrete source-written/release artifacts:

| Artifact | Source evidence | Resolution |
|---|---|---|
| `sensor-preflight.json` | `cli.py:426-432`, `workflow.py:158` | Added to `SCHEMAS.md` |
| `benign-procedure-gap-report.json` | `benign_procedures.py:43-46` | Added to `SCHEMAS.md` |
| `cleanup.json` | `benign_procedures.py:53` | Added to `SCHEMAS.md` |
| `integration.json` | `idpt.py:262` | Added to `SCHEMAS.md` |
| `adversaryflow-source.zip` | `scripts/release.py:34-40` | Added to `SCHEMAS.md` |
| `sbom.cdx.json` | `scripts/release.py:49-51` | Added to `SCHEMAS.md` |

The existing schema identifiers and primary artifact families are documented in `docs/SCHEMAS.md:5-35`; the new source-derived contract checks concrete literal artifact names associated with write operations.

### Tested behavior

The full behavior test run passed with a repository-local pytest base directory: `210 passed in 14.34s`. The coverage-enabled run also passed all 210 tests on this host's Python 3.14: `95.05%` total coverage with the exact `--cov-fail-under=95` gate. The added regression covers the fail-closed guard that rejects re-approval of a campaign whose status is not `awaiting-approval`. The CI workflow tests Python 3.11 and 3.12; the latest remote CI run for commit `3d277f7` passed all jobs. The repository-local-base run is the authoritative result for this checkout.

The test suite has direct coverage for campaign persistence and lifecycle decisions (`tests/test_campaign_persistence.py`, `tests/test_lifecycle.py`), manager approval and routes (`tests/test_manager_approval.py`, `tests/test_profiles_manager.py`), artifacts (`tests/test_artifact_journey.py`, `tests/test_reports.py`, `tests/test_product_tools.py`), provider/environment behavior (`tests/test_provider.py`, `tests/test_provider_client.py`), telemetry and detection (`tests/test_telemetry.py`, `tests/test_extended_features.py`), IDPT boundaries (`tests/test_idpt.py`), and documentation validators (`tests/test_validation_coverage.py`).

The documentation checks themselves passed:

```text
python scripts/validate_documentation.py       documentation validation passed
python scripts/documentation_gap_analysis.py   Documentation gap analysis passed
python scripts/source_documentation_contract.py Source/documentation contract passed
```

The local checks emitted only the existing doctor warning that it could not read the unmanaged WindowsApps installation directory; the three documentation commands still returned success.

## Enforcement added

`scripts/source_documentation_contract.py` now performs source-derived parity checks for parser commands/options/defaults, manager routes, `ADVERSARYFLOW_*` environment names, and concrete serialized artifact names. `.github/workflows/ci.yml:24-30` runs it on the existing test job, so a future source change that is not reflected in the relevant documentation fails CI.

This check is deliberately literal and fail-closed. It does not infer undocumented behavior, generate prose, or certify runtime behavior that is not covered by tests.

## Remaining limits

The repository does not contain a formal machine-readable mapping from every prose sentence to a test. Therefore this audit can prove source/document parity for the checked surfaces, and can identify test modules and the observed test result, but it cannot claim that every sentence in every Markdown document is behaviorally tested. Any future requirement for sentence-level provenance would need an explicit mapping format and test policy.
