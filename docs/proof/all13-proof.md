# Local proof of all thirteen remediations

Implementation commit: `8286703ad5e3b25a54606f73a828c9e22cf0c562`.

Implementation tree: `d05b4403ec6e989b75fa6d4ee8f53015ba5e5b3f`.

Baseline: `6270a61ec85e444a4649add84c0f09b3410498d2`.

The work stays on local `main` in `C:\Users\tsaxon\Documents\Github\AdversaryFlow`.
No push, pull request, upload, or repository network operation was performed.
The implementation and proof are separate commits so neither needs to hash itself.

## Verify the proof

The 48,036,051-byte bundle is at:

```text
C:\Users\tsaxon\.copilot\session-state\85e5a5d5-d498-4fe9-becb-dc52c2bb36fa\files\AdversaryFlow-all13-proof.zip
```

Its separately pinned SHA-256 is:

```text
1a0bd1cb62dc86c8f88af0241a232bdfea26c37039977980c4131d2ee5cfef22
```

From the checkout, run:

```powershell
$proof = Get-Content docs\proof\all13-pin.json -Raw | ConvertFrom-Json
.venv\Scripts\python.exe scripts\verify_local_proof.py $proof.bundle --sha256 $proof.bundle_sha256
```

The verifier passed with exit code 0. It checks the outer digest, every declared
file's digest and byte size, the exact ZIP file set, thirteen finding IDs, passing
final command results, and the implementation's Git tree and baseline parent.
Eight regression tests also reject changed files, changed bundles, omitted cases,
failed final checks, invalid Git identities, wrong trees, and undeclared files.

The bundle contains a self-contained source tar, an incremental Git bundle,
wheel/source distributions, actual PDF/extracted-text/raster artifacts, tool
versions, capture/assembly helpers, and stdout/stderr with real command arguments,
UTC start/end times, durations and exit codes. Its manifest names the actually
executed per-finding regressions and their assertions. Earlier captured failed
attempts are separate from passing final gates. The incremental Git bundle requires
the declared baseline; the source tar does not.

## Disposition and regression mapping

All thirteen findings are fixed. Exact expanded test IDs are in `manifest.json`.

| Finding | Fix and regression |
|---|---|
| F01 | Begin confirmation, full-workspace cancel preservation and intentional clearing: `App.test.tsx`. |
| F02 | Reactive persistence failure across scope/workflow/import/archive writes and review re-entry: `remediation.test.ts` and `App.test.tsx`. |
| F03 | Exact UTF-8 boundary -1/equal/+1, Unicode and 1,400 large schema 3 procedures with HTTP restore/save consistency: `remediation.test.ts` and `test_all13_regressions.py`. |
| F04 | Actual boundary file roundtrip, original-wrapper support, denied storage, unsafe/malformed rejection and explicit reset confirmation: `ErrorBoundary.test.tsx` and `remediation.test.ts`. |
| F05 | Fresh-browser engagement/revision browsing, empty/error/retry, replacement confirmation and subsequent append: `SavedEngagements.test.tsx` and `App.test.tsx`. |
| F06 | Guardrail alone leaves restricted imports withheld; explicit authenticated catalog reload preserves snapshots/provenance and platform gaps: `remediation.test.ts`; App wires session authorization, reload confirmation and scope review. |
| F07 | Same source/candidate retained independently for two actors; actor-filtered unique export: `remediation.test.ts`. |
| F08 | Accept/attach/reimport/reject revokes evidence, including matching archives, without affecting other actors/sources or autoattaching unrequested candidates: `IntelligenceImportPanel.test.tsx` and `remediation.test.ts`. |
| F09 | Imported execution attribution survives notes/detection/cleanup, explicit empty context remains empty, missing context remains absent and only new records default from scope: parameterized `remediation.test.ts` cases. Existing receipt-invalidation coverage remains passing. |
| F10 | 20/21 references, 500/501 Unicode code points, deduplication and recoverable drafts; invalid/legacy content is retained rather than truncated: `remediation.test.ts`, `TechniqueCard.test.tsx` and `exportModel.test.ts`. |
| F11 | All skipped means zero executed; reviewed/skipped/mixed counts and import/export roundtrip remain truthful; reports retain occurrence multiplicity: `remediation.test.ts` and `test_all13_regressions.py`. |
| F12 | Hung fetch, full preparation deadline, cancellation, bounded auth/CSRF retries, stale startup/save/report prevention and reachable retry: `client.test.ts`, `App.test.tsx`, `ExportScreen.test.tsx`, and browser UAT E5 on all three engines. |
| F13 | Real PDF extraction and rasterized glyph ink, embedded font/ToUnicode, explicit emoji marker, pagination and offline native/wheel/container output: `test_all13_regressions.py` plus the bundle's PDF artifacts. |

## Recorded final gates

| Command | Actual result |
|---|---|
| `npm run check:frontend` | Typecheck/build passed; 74 tests passed in 14 files. |
| `npm run test:frontend -- --reporter=verbose` | All 74 named regressions passed. |
| `npm run test:e2e` | 276 passed across Chromium, Firefox and WebKit, including real-service cases and accessibility. |
| `.venv\Scripts\python.exe -m unittest discover --verbose` | 504 discovered; 503 executed successfully; one existing platform skip. |
| `.venv\Scripts\python.exe -m ruff check .` | Passed. |
| `.venv\Scripts\python.exe -m mypy` | Passed for 70 source files. |
| `npm run check:frontend-assets` | Passed after the implementation commit; generated assets synchronized. |
| `.venv\Scripts\python.exe -m build --no-isolation --outdir <recorded-artifact-directory>` | Wheel and source distribution built successfully. |
| `.venv\Scripts\python.exe scripts\verify_distribution_assets.py --dist-dir <recorded-artifact-directory>` | Font/license/frontend byte equality and rebuild inputs passed. |
| `.venv\Scripts\python.exe scripts\compose_smoke.py --fresh` | Fresh isolated Docker build and authenticated readiness passed; test containers/volumes removed. |
| `pdf_proof.py --label native`, installed-wheel invocation, and `--label container --image <recorded-image>` | Actual extraction and PDFium rendering passed. Container execution used `--network none`; all three representative PDF digests match. |

The log result JSON files contain each full argv, including artifact directories,
the normally installed wheel interpreter/prefix, and the actual container image.
Wheel verification reused existing native dependency packages through `PYTHONPATH`;
it is not a clean dependency-install certification. The one skipped existing test
uses POSIX executable stubs; its native Windows installer run belongs to CI.

## Meaning and limits

Git content-addressing and the independently retained SHA-256 pin make changed
content detectable. They do **not** independently authenticate authorship, provide
trusted timestamps, or prevent deletion or replacement of every copy of the pin.
UTC times are the local host clock. Keep a separate copy of the bundle and pin if
the session artifact directory will be deleted.

The offline licensed Noto font covers the tested Chinese/Cyrillic/BMP symbols.
Unsupported glyphs and non-BMP emoji render as explicit `[U+...]` code-point markers,
not silently substituted question marks; the PDF explains this and HTML preserves
the original text. No proprietary OS font or runtime font download is used.
