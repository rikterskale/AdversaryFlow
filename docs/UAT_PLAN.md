# AdversaryFlow — User Acceptance Test Plan

Covers every row of the journey map in [USER_JOURNEY.md](USER_JOURNEY.md),
plus the boundary inputs the accepted behaviour depends on.

**Case IDs** — `J1`–`J62` are the journey-map rows. `B1`–`B38` are plan-import
boundaries. `B39`–`B47` are service and catalog boundaries. `E1`–`E16` cover
the additional alternate and recovery paths documented outside the journey
map.

**How to read the Steps column** — cases marked *(auto)* are executed by the
named test in the repository's own suites and are re-run by CI. Cases marked
*(manual)* were executed from a terminal against a live service and the real
ATT&CK enterprise bundle; their captured output is the Actual result.

## Environment of record

| Item | Value |
|---|---|
| Build | AdversaryFlow 0.4.0 |
| Python | 3.14.4 (CPython, Linux) |
| Node | v24.19.0, Playwright 1.62.1, Chromium |
| PowerShell | 7.6.5 (`Core`, Linux host) |
| ATT&CK data | `enterprise:bundle--6198013c-6f02-42a4-9713-38ea1301a1aa` (232 actors) |
| Service under test | `http://127.0.0.1:5055`, loopback, offline mode against the cached bundle |
| Suites | `python -m unittest discover`, `npm run test:e2e`, Ruff, mypy, JavaScript/Bash/PowerShell syntax and launcher checks |

---

## A. Happy path — primary journey

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| J1 | Clean source checkout, Python ≥ 3.10 | `./install.sh` *(manual)* | stdout ends `AdversaryFlow installed and verified.`; exit 0 | From an isolated source archive with no `.venv`: installed both hash-locked sets, built the editable package, doctor reported `ok = true`, then printed `AdversaryFlow installed and verified. Start it with ./run.sh`; exit 0 | **Pass** |
| J2 | Installed | `adversaryflow --version` *(manual)*; `test_uat.py::test_j02_the_version_is_reported` *(auto)* | stdout exactly `AdversaryFlow 0.4.0` | `AdversaryFlow 0.4.0`; exit 0 | **Pass** |
| J3 | Installed | `adversaryflow doctor` *(manual)*; `test_j03_doctor_reports_a_healthy_install` *(auto)* | exit 0; `ok`, `frontend_available`, `cache_writable` all true | `ok = True, frontend_available = True, cache_writable = True, version = 0.4.0, deps = {Flask: 3.1.3, waitress: 3.0.2}`; exit 0 | **Pass** |
| J4 | Installed, cache seeded | `./run.sh` *(manual)* | stdout announces the service URL | `[AdversaryFlow] starting; the browser will open when ATT&CK data is ready` / `AdversaryFlow 0.4.0: http://127.0.0.1:5057`; `/api/live` returned `live` | **Pass** |
| J5 | Service running | `curl http://127.0.0.1:5055/` *(manual)*; `test_j05_the_wizard_page_is_served` *(auto)* | HTTP 200 with the wizard title | `HTTP 200`, `<title>AdversaryFlow — Adversary Emulation Planner</title>` | **Pass** |
| J6 | Service running | `curl -D - /api/session` *(manual)*; `test_j06_every_response_is_hardened` *(auto)* | nosniff, no-referrer, same-origin, request id, CSP with `frame-ancestors 'none'` | All five headers present; CSP contained `frame-ancestors 'none'`; request ID was non-empty | **Pass** |
| J7 | Service running | `test_j07_a_session_token_is_issued` *(auto)* | Non-empty `csrf_token` and `version` | Token issued; `version = 0.4.0` | **Pass** |
| J8 | Data not yet loaded | `test_j08_bootstrap_starts_and_reaches_ready` *(auto)* | POST 200/202, then `runtime.ready = true` | POST accepted; poll returned `ready = true` | **Pass** |
| J9 | Before / after load | `test_j09_health_is_degraded_before_data_is_ready`, `…_ready_once_data_is_loaded` *(auto)*; live curl *(manual)* | 503 `degraded`, then 200 `ready` | 503 `degraded`; live service `status = ready, ready = True, phase = ready, version = 0.4.0` | **Pass** |
| J10 | UI reachable | `uat.spec.js` J10 *(auto)* | Welcome heading and enabled start button | Heading, enabled button, and the "does not execute commands" footer all visible | **Pass** |
| J11 | Actors loaded | `uat.spec.js` J11 *(auto)* | `#dataStatus` matches `^\d+ actors? · Enterprise$` | Matched | **Pass** |
| J12 | Data loaded | `test_j12_actor_records_carry_the_published_contract` plus ATT&CK deprecation tests *(auto)*; live curl *(manual)* | Every actor carries the seven published fields; live enterprise catalog includes every mapped non-deprecated group and campaign and omits revoked/deprecated objects and relationships | Contract violations = 0; `actors = 232`; `groups = 176`; `campaigns = 56`; actor/technique fixture tests omitted every revoked or deprecated object and relation | **Pass** |
| J13 | On step 1 | `uat.spec.js` J13 *(auto)* | Footer changes to `Selected: <name>`; Continue enabled | `Select a threat actor to continue` → `Selected: UAT Actor`; Continue enabled | **Pass** |
| J14 | On step 1 | `uat.spec.js` J14 *(auto)* | Search narrows the grid; clear restores it | 2 cards → 1 card → 2 cards | **Pass** |
| J15 | On step 1 | `uat.spec.js` J15 *(auto)* | Empty state shown, no cards | `No actors match your search.` visible; 0 cards | **Pass** |
| J16 | Actor selected | `test_j16_the_workflow_is_ordered_and_fully_commanded` *(auto)*; live curl *(manual)* | Exact key set, kill-chain order, every technique commanded | Keys `['actor','kill_chain','metadata','stages','summary']`; APT29 `techniques=66 curated=66 fallback=0 stages=13`; stage order matched `kill_chain`; techniques with no command = 0 | **Pass** |
| J17 | Workflow built | `uat.spec.js` J17 *(auto)* | Scope heading and live preview | `1 runnable · 0 unsupported across 1 stages`; preview names the actor | **Pass** |
| J22 | Scope set | `uat.spec.js` J22 *(auto)* | Plan opens on the first stage with the command shown | Heading `UAT Actor · G0001`; 3 rail items; first stage `Execution`; command `whoami` | **Pass** |
| J23 | Plan open | `uat.spec.js` J23 *(auto)* | Risk badge, Effects, Expected telemetry visible | `high risk` badge, `Effects:`, `Expected:`, `cleanup required`; expanding ATT&CK context shows detection text and a data-source chip | **Pass** |
| J24 | Multi-stage plan | `uat.spec.js` J24 *(auto)* | Forward/back/rail navigation with correct disabled ends | Execution → Persistence → Impact → back to Persistence → rail to Execution; ends disabled correctly | **Pass** |
| J25 | Risky command in scope | `uat.spec.js` J25 *(auto)* | Confirm dialog, then clipboard + toast | In-app dialog `Copy this high risk lab command?` showing the command; toast `Command copied to clipboard`; clipboard held the exact command | **Pass** |
| J26 | Plan open | `uat.spec.js` J26 plus receipt-import browser test *(auto)* | Progress advances and structured execution proof persists | `0 / 3` / `0%` → `1 / 3` / `33%`; command and detection selects update without wiping the evidence note; a valid receipt populated run ID, timestamps, exit code, cleanup and verified digest in the schema-valid JSON export | **Pass** |
| J28 | Plan walked | `uat.spec.js` J28 *(auto)* | Export screen with four stat tiles | Heading shown; tiles Techniques, Stages, Runnable tests, Marked run; footer `Plan complete` | **Pass** |
| J29 | On step 4 | **Generate report**, then JSON; `uat.spec.js` J29 *(auto)* | JSON validates against the published schema | Preview reached ready; `AdversaryFlow_G0001_UAT_Actor.json` valid per Ajv 2020; outcome `passed`, note `Observed` round-tripped | **Pass** |
| J30 | On step 4 | `uat.spec.js` J30 *(auto)* | Markdown report with heading, technique, outcome, command | `# AdversaryFlow — UAT Actor (G0001)`, `### T1059.001 — PowerShell`, `**Outcome:** failed`, `**Detection:** not_assessed`, `whoami` | **Pass** |
| J31 | On step 4 | `uat.spec.js` J31 *(auto)* | Non-executable `.txt` runbook with every physical metadata, command, and cleanup line commented, including imported multiline values | Runbook contained the expected `REM` headers/outcome/detection/command; a hostile multiline import produced zero non-empty lines without `REM` | **Pass** |
| J32 | A saved JSON plan exists | `uat.spec.js` J32 *(auto)* | Plan restored with evidence and guardrails intact | Toast `Plan imported with its saved guardrails…`; heading `UAT Actor · G0001`; outcome `passed`; note `Script block logging fired` | **Pass** |
| J54 | Real bundle and catalog available | Resolve every actor-mapped technique, inspect the exercise registry, and execute every bounded exercise *(manual plus `test_catalog.py` / `test_lab_exercises.py` auto)* | 0 mapped techniques use the runtime fallback; every one of the 146 bounded entries has a technique-relevant scenario and valid receipt | `actors=232 mapped=536 fallback=0`; `540` technique keys, `856` command records; `146` exercise IDs each available on Windows/Linux/macOS across `25` scenario families; all 146 passed, cleaned up, and produced a valid SHA-256 receipt | **Pass** |
| J59 | OpenAPI contract present | Inspect `docs/openapi.yaml` *(auto: `test_openapi_documents_conditional_bearer_auth_and_every_401`)* | HTTP bearer scheme, conditional remote-mode requirement, and a 401 for every operation | `BearerToken` is `type: http`, `scheme: bearer`; conditional security block present; nine operations each declare 401 | **Pass** |
| J60 | Export screen open | Click **Download Windows execution kit** *(auto: `uat.spec.js` J60 plus execution-kit unit tests)* | Catalog-rebound ZIP downloads with CSV and platform runner; bounded plans include exercise script | Download `AdversaryFlow_G0001_UAT_Actor_Windows.zip`; submitted schema 2.0 plan; toast `Execution kit ready`; backend ZIP tests found `-plan.csv`, `-execute.ps1`/`.sh`, and conditional `AdversaryFlow-exercises.py` | **Pass** |
| J63 | Export screen open | Click **Generate report**, inspect preview, download HTML/PDF/JSON *(auto: `wizard.spec.js` report journey, `ExportScreen.test.tsx`, and `test_reporting.py`)* | Explicit empty/loading/error/ready states; command-free HTML/PDF; schema 2.0 JSON; accurate telemetry, detection, evidence, and gaps | Sandboxed preview reached ready; all three filenames matched; fixture assertions covered order, telemetry acceptance, curated/fallback and detection math, explicit Sigma gaps, and command omission | **Pass** |

---

## B. Alternate and error paths

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| J18 | Plan built on Windows | Back → **Linux** → return to the plan *(auto: `uat.spec.js` J18)* | No cross-OS substitution; unsupported state and disabled copy | Preview `Runnable on Linux`; footer `0 runnable · 1 unsupported across 1 stages`; card `No Linux test is available for this technique.`; Copy disabled | **Pass** |
| J19 | On step 2 | Click **Clear all** *(auto: J19)* | Plan empties; Build plan disabled; label flips | `Clear all` → `Select all`; footer `No techniques in scope — enable a stage`; Build plan disabled | **Pass** |
| J20 | High-risk command, allowance withdrawn | *(auto: J20)* | Command withheld with both copy buttons disabled | Card `Restricted by scope: high-risk commands are disabled.`; Copy command and Copy cleanup both disabled | **Pass** |
| J21 | Same, allowance granted | *(auto: J21)* | Command restored and counted runnable | Footer `1 runnable · 0 unsupported across 1 stages`; real `schtasks /Create …` shown | **Pass** |
| J27 | `Storage.setItem` throws | *(auto: J27)* | Operator is warned, not silently dropped | Toast `Progress can't be saved in this browser — export the plan to keep your records` | **Pass** |
| J33 | Export made with default scope | Re-import that file *(auto: J33)* | Resumed plan is usable, not blocked by its own risk elevation | Export had `allow_high_risk: false`; re-import showed `whoami`, no `Restricted by scope`, footer `/ 1 runnable` | **Pass** |
| J34 | Plan with an incomplete actor | *(auto: J34)* | Refused; welcome screen intact | Toast `Plan actor record is invalid`; welcome heading still displayed | **Pass** |
| J35 | Plan with `schema_version: "1.0"` | *(auto: J35)* | Refused | Toast `This is not an AdversaryFlow 2.0 plan export`; welcome heading still displayed | **Pass** |
| J36 | Finished plan, filters changed | **Plan another actor** → **Begin emulation plan** *(auto: J36)* | Picker filters reset | Domain Enterprise `aria-pressed=true`, ICS `false`, type `All` true, sort `name`, footer `Select a threat actor to continue` | **Pass** |
| J37 | Previous actor had operator/target | Select a different actor *(auto: J37)* | Execution record starts empty | Operator `""`, Target `""` | **Pass** |
| J38 | `GET /api/session` returns 500 | *(auto: J38)* | Actionable failure with a retry | `ATT&CK cache is unreadable` shown; chip `setup needs attention`; **Retry setup** present | **Pass** |
| J39 | Fault cleared | Click **Retry setup** *(auto: J38, second half)* | Session recovers without a reload | Actor grid rendered; chip back to `<n> actors · Enterprise` | **Pass** |
| J40 | Service running | `GET /api/actors?domains=bogus` *(auto: `test_j40…`; manual curl)* | 400 with the standard envelope | `HTTP 400 {"error":"bad_request","message":"Unknown ATT&CK domain(s): bogus","version":"0.4.0"}` | **Pass** |
| J41 | Service running | `GET /api/workflow/intrusion-set--nope` *(auto: `test_j41…`; manual curl)* | 404 with error, message and version | `HTTP 404 {"error":"actor_not_found","message":"No ATT&CK group or campaign matches intrusion-set--nope in the selected domains.","version":"0.4.0"}` | **Pass** |
| J42 | Service running | `POST /api/refresh` with no CSRF header *(auto: `test_j42…`)* | 403 | `403 {"error":"forbidden"}` | **Pass** |
| J43 | Service running | `POST /api/refresh?domains=bogus`, then a valid refresh *(auto: `test_j43…`)* | The rejected call does not wedge the endpoint | First 400; `_refresh_lock.locked()` False; valid refresh 200 | **Pass** |
| J44 | Service running | Two valid refreshes inside 5 s *(auto: `test_j44…`)* | Second is throttled | 200 then `429 {"error":"refresh_rate_limited"}` | **Pass** |
| J45 | CLI available | `--host 0.0.0.0 --no-preload` *(auto: `test_j45…`)* | Refuses to start | exit 2, `Refusing a non-loopback bind without --allow-remote.` | **Pass** |
| J46 | CLI available | `--host 0.0.0.0 --allow-remote --no-preload` *(auto: `test_j46…`)* | Refuses without a token | exit 2, `Refusing a non-loopback bind without --api-token` | **Pass** |
| J47 | Remote mode with a token | Request with no / wrong / right token *(auto: `test_j47…`)* | Only the right token is admitted | 401, 401, 200 | **Pass** |
| J48 | CLI available | `cache-status` *(auto: `test_j48…`)* | All three domains reported | exit 0; `{enterprise, ics, mobile}`, each with `path` and `exists` | **Pass** |
| J49 | CLI available | `cache-clear` with no `--yes` *(auto: `test_j49…`)* | Refuses | exit 2, `Refusing to clear the cache without --yes.` | **Pass** |
| J50 | Cache dir holds a bundle and an unrelated file | `cache-clear --yes` *(auto: `test_j50…`)* | Only AdversaryFlow files removed | exit 0; bundle listed in `removed` and deleted; `operator-notes.txt` survived unchanged | **Pass** |
| J51 | CLI available | `cache-refresh --domains bogus` *(auto: `test_j51…`)* | Refuses | exit 2, `Unknown ATT&CK domain(s): bogus` | **Pass** |
| J52 | Cache seeded, `--offline` | Serve and query the API *(manual)* | Served from cache with no upstream request | `offline = true`, enterprise cache `exists = true` (stale was accepted offline); service reached `ready` and served 232 actors | **Pass** |
| J53 | Empty cache dir, `--offline` | `load_bundle("enterprise")` *(auto: `test_j53…`)* | Actionable error | `RuntimeError: offline mode requires a cached enterprise ATT&CK bundle at <path>` | **Pass** |
| J55 | UI reachable | axe-core scan of step 0 *(auto: `uat.spec.js` J55)* | No serious or critical violations | `[]` | **Pass** |
| J57 | Valid CSRF token | Send mutations with foreign host, wrong scheme, wrong port, `null`, then matching IPv6 origin *(auto: `test_j57_mutations_require_an_exact_origin`)* | Four mismatches rejected; exact IPv6 accepted | `403 forbidden` for all four mismatches; `http://[::1]:5000` with matching host returned 200 | **Pass** |
| J58 | PowerShell 7 available | Force venv, runtime dependency, build dependency, editable package, and doctor child processes to fail *(auto: `test_j58_powershell_installer_stops_after_every_native_failure`)* | Every failure terminates at its step and no success message appears | Five subcases exited non-zero with their step-specific error; zero printed `AdversaryFlow installed and verified.` | **Pass** |
| J61 | Export screen open; execution-kit API returns 400 | Click execution-kit card *(auto: `uat.spec.js` J61)* | API message shown, no download, retry remains enabled | Toast `Plan contains no executable Windows steps`; downloads = 0; button enabled | **Pass** |
| J62 | A downloaded Linux kit whose step exits 3 and whose cleanup exits 4 | Run the kit to completion *(auto: `test_execution_kit.py::test_linux_runner_records_a_failing_step_and_cleanup_with_full_evidence`, `…::test_posix_runner_never_enables_errexit`; also run live from a terminal)* | The failure is recorded as evidence; the session completes and writes the full evidence set; the runner never enables errexit | Runner exit 0; evidence dir held `SHA256SUMS commands evidence-events.jsonl execution-report.html execution-report.md execution-results.csv execution-summary.json stdout stderr`; summary `status=completed failed_steps=1 completed_steps=0`; CSV row `exit_code=3 execution_status=completed assessment=failed cleanup_status=failed`; `set -e` statements in the generated runner = 0 | **Pass** |

---

## C. Boundary inputs

### C.1 Plan import contract — executed in the loaded page against the shipped validator

*(auto: `uat.spec.js` "J56 — the import contract holds at every documented limit")*

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| J56 | Loaded page and generated boundary documents | Validate all 38 cases below | Every inclusive limit is accepted; every over-limit or malformed value is rejected without changing screens | 38/38 validator cases returned the expected result; welcome screen remained usable | **Pass** |
| B1 | Valid schema 2.0 plan | Validate | Accepted | accepted | **Pass** |
| B2 | `schema_version: "1.0"` | Validate | `This is not an AdversaryFlow 2.0 plan export` | as expected | **Pass** |
| B3 | `tool: "AnotherTool"` | Validate | `This is not an AdversaryFlow 2.0 plan export` | as expected | **Pass** |
| B4 | `tool_version: ""` | Validate | `Plan is missing its tool or ATT&CK data version` | as expected | **Pass** |
| B5 | `data_version: ""` | Validate | `Plan is missing its tool or ATT&CK data version` | as expected | **Pass** |
| B6 | Invalid `generated` timestamp | Validate | `Plan generated timestamp is invalid` | as expected | **Pass** |
| B7 | Unknown top-level field | Validate | `Plan contains unknown or missing top-level fields` | as expected | **Pass** |
| B8 | Actor without `aliases` | Validate | `Plan actor record is invalid` | as expected | **Pass** |
| B9 | Actor `type: "threat"` | Validate | `Plan actor record is invalid` | as expected | **Pass** |
| B10 | `technique_count: -1` | Validate | `Plan actor record is invalid` | as expected | **Pass** |
| B11 | Unknown actor field | Validate | `Plan actor record is invalid` | as expected | **Pass** |
| B12 | `domains: ["galaxy"]` | Validate | `Plan contains an invalid ATT&CK domain` | as expected | **Pass** |
| B13 | `domains: []` | Validate | `Plan contains an invalid ATT&CK domain` | as expected | **Pass** |
| B14 | Duplicate domains | Validate | `Plan contains an invalid ATT&CK domain` | as expected | **Pass** |
| B15 | `command_platform: "plan9"` | Validate | `Plan scope is invalid` | as expected | **Pass** |
| B16 | `allow_high_risk: "yes"` | Validate | `Plan scope is invalid` | as expected | **Pass** |
| B17 | Duplicate scope stages | Validate | `Plan scope is invalid` | as expected | **Pass** |
| B18 | `execution_context` absent | Validate | `Plan execution context is invalid` | as expected | **Pass** |
| B19 | `execution_context` non-string fields | Validate | `Plan execution context is invalid` | as expected | **Pass** |
| B20 | Operator longer than 120 characters | Validate | `Plan execution context is invalid` | as expected | **Pass** |
| B21 | Negative summary count | Validate | `Plan summary is invalid` | as expected | **Pass** |
| B22 | Zero stages | Validate | `Plan stage count is invalid` | as expected | **Pass** |
| B23 | Exactly 32 non-empty stages | Validate | Accepted | accepted | **Pass** |
| B24 | 33 stages | Validate | `Plan stage count is invalid` | as expected | **Pass** |
| B25 | Empty stage | Validate | `Plan contains an invalid stage` | as expected | **Pass** |
| B26 | Stage without a title | Validate | `Plan contains an invalid stage` | as expected | **Pass** |
| B27 | Malformed technique ID | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B28 | Technique without a name | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B29 | `platforms` not an array | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B30 | Invalid technique URL | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B31 | Command of exactly 10,000 characters | Validate | Accepted | accepted | **Pass** |
| B32 | Command of 10,001 characters | Validate | `Plan contains an invalid command record` | as expected | **Pass** |
| B33 | Command without a risk value | Validate | `Plan contains an invalid command record` | as expected | **Pass** |
| B34 | Invalid execution outcome | Validate | `Plan execution record is invalid` | as expected | **Pass** |
| B35 | Exactly 2,000 techniques in one stage | Validate | Accepted | accepted | **Pass** |
| B36 | 2,001 techniques in one stage | Validate | `Plan contains too many technique records` | as expected | **Pass** |
| B37 | Exactly 4,000 aggregate techniques | Validate | Accepted | accepted | **Pass** |
| B38 | 4,001 aggregate techniques | Validate | `Plan exceeds the 4000-technique limit` | as expected | **Pass** |

### C.2 Service and catalog boundaries

*(auto: `tests/test_uat.py::BoundaryUatTests`)*

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| B39 | Service running | `GET /api/actors?domains=` | Falls back to `enterprise` | `["enterprise"]` | **Pass** |
| B40 | Service running | `GET /api/actors?domains=%20,%20` | Falls back to `enterprise` | `["enterprise"]` | **Pass** |
| B41 | Service running | `GET /api/actors?domains=enterprise,ics,mobile` | All three accepted in order | `["enterprise","ics","mobile"]` | **Pass** |
| B42 | Service running | `GET /api/actors?domains=enterprise,bogus` | One bad value rejects the request | HTTP 400 | **Pass** |
| B43 | Service running | `POST /api/refresh` with a 17,850-byte body (limit 16,384) | Rejected; unauthenticated before the body is read | No token → 403; with token → 413 `request_entity_too_large` | **Pass** |
| B44 | Service running | `POST /api/refresh` with a body under the limit | Accepted | HTTP 200 | **Pass** |
| B45 | Catalog loaded | `get_commands("T9999", …, ["execution"])` | Exactly one fallback command naming the technique | `source = fallback`, 1 command containing `T9999` | **Pass** |
| B46 | Catalog loaded | `get_commands("T9999", …, [])` | Still returns a runnable command | `source = fallback`, non-empty command | **Pass** |
| B47 | Catalog loaded | Inspect all 856 command records | Every risk is low/medium/high; medium and high require acknowledgement | All records conform | **Pass** |

---

## D. Additional alternate and error paths

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| E1 | Installer checkout | Run `install.sh` with no `python3`, then a fake Python 3.9.18 *(auto: `test_install_script_rejects_missing_and_old_python`)* | Both exit 1 with the documented prerequisite message | Missing Python and Python 3.9.18 subcases each exited 1 with the exact message | **Pass** |
| E2 | One process owns the requested port | Start another AdversaryFlow instance on that port *(manual)* | Second waitress process refuses the bind; alternate port starts | Second launch exited non-zero with `Address already in use`; launch on the alternate test port answered `/api/live` | **Pass** |
| E3 | Remote service returns 401 until a bearer token is supplied | Start remote mode and enter a token in the in-app dialog *(auto: `test_e03_remote_mode_warns_before_serving` plus `wizard.spec.js` remote-access test)* | CLI warns that every API call needs bearer auth; accessible dialog stores accepted token only in session storage and continues | Exact CLI warning printed; dialog accepted `fixture-token`, closed, welcome screen rendered, and `sessionStorage.af_api_token` matched | **Pass** |
| E4 | Bootstrap GET returns 503 and POST returns 403 | Load the page *(auto: `uat.spec.js` E4)* | Loader stops; backend message, attention status, and retry appear | Exact CSRF error shown; status `setup needs attention`; **Retry setup** visible | **Pass** |
| E5 | Bootstrap remains loading beyond its deadline | Load with the clock advanced past 15 minutes *(auto: `uat.spec.js` E5)* | Timeout message and retry appear | Exact `Preparing ATT&CK data timed out…` message and **Retry setup** visible | **Pass** |
| E6 | Actor API fails after the picker is usable | Change domains, then restore API and click **Retry setup** *(auto: `uat.spec.js` E6)* | Backend message is visible; retry reloads actors without a browser reload | `ATT&CK backend unavailable`, `setup needs attention`, then recovered to `2 actors · Enterprise + Ics` | **Pass** |
| E7 | Download declares or streams more than 128 MiB, or is not STIX | Invoke data download *(auto: `CacheLifecycleTests`)* | Partial file removed and cache not replaced | Declared-size, streamed-size, and non-bundle tests raised the documented error; destination absent | **Pass** |
| E8 | Stale valid cache; refresh download fails | Load bundle *(auto: `test_a_failed_refresh_serves_the_stale_cache_and_records_the_error`)* | Existing data served and cache status records stale/error | Bundle `bundle--test` served; `stale = true`; `refresh_error` contained `network down` | **Pass** |
| E9 | Online cache contains corrupt JSON | Load bundle *(auto: `test_a_corrupt_cache_triggers_an_unconditional_redownload`)* | Unconditional replacement succeeds | Conditional flag was false and repaired bundle `bundle--repaired` loaded | **Pass** |
| E10 | Offline cache contains corrupt JSON | Load bundle *(auto: `test_offline_load_of_a_corrupt_cache_is_actionable`)* | Actionable reconnect/refresh error | Raised `is invalid; reconnect and refresh` | **Pass** |
| E11 | Enterprise is the only selected domain | Click Enterprise *(auto: `uat.spec.js` E11)* | Toast warns and Enterprise remains selected | Toast `Keep at least one ATT&CK domain selected`; `aria-pressed=true` | **Pass** |
| E12 | Browser rejects clipboard writes | Click **Copy command** *(auto: `uat.spec.js` E12)* | Denial toast shown | Toast `Clipboard access was denied` | **Pass** |
| E13 | A plan is open | Click refresh, cancel, then confirm *(auto: `uat.spec.js` E13)* | Cancel preserves plan; confirm rebuilds and returns to picker | Plan remained after cancel; confirmed refresh returned to picker with `ATT&CK feed refreshed; the plan was rebuilt` | **Pass** |
| E14 | Refresh is already active or bootstrap is loading | POST refresh *(auto: `test_e14_refresh_conflicts_name_the_active_operation`)* | Returns `409 refresh_in_progress` or `409 bootstrap_in_progress` | Both 409 envelopes observed and named the active operation | **Pass** |
| E15 | Welcome screen | Select a JSON file of 5 MiB + 1 byte *(auto: `uat.spec.js` E15)* | File rejected before parsing and welcome remains usable | Toast `Plan file is larger than 5 MB`; welcome heading remained visible | **Pass** |
| E16 | Known domain and mocked downloader | `cache-refresh --domains enterprise` *(auto: `test_cache_refresh_accepts_known_domains`)* | Refresh completes and prints cache status | Exit 0; enterprise refresh result emitted | **Pass** |

---

## E. Cases requiring human judgment

These are **not** automated and were not claimed as passed. They need a person
with a lab and a detection platform.

| Area | Why it needs a human |
|---|---|
| Whether a copied command actually fires the operator's detection | Depends on the operator's EDR/SIEM, not on AdversaryFlow |
| Whether an exported Markdown report reads well for a given audience | Editorial judgment |
| Real browser-to-clipboard behaviour under a corporate policy | Environment-specific |
| Behaviour of a genuine first-run download on a metered or proxied network | Requires that network |

---

## F. Execution summary

Executed on the environment of record above.

| Group | Cases | Pass | Fail |
|---|---|---|---|
| A. Happy path (journey rows) | 30 | 30 | 0 |
| B. Alternate and error paths (journey rows) | 31 | 31 | 0 |
| C.1 Journey boundary row | 1 | 1 | 0 |
| C.1 Plan-import boundaries | 38 | 38 | 0 |
| C.2 Service and catalog boundaries | 9 | 9 | 0 |
| D. Additional alternate and error paths | 16 | 16 | 0 |
| **Total** | **125** | **125** | **0** |

Every journey-map row `J1`–`J62` is covered exactly once across groups A, B,
and the J56 row in C.1. Every alternate/error row in `USER_JOURNEY.md` maps to
one of those journey cases or E1–E16.

### Suites executed

```text
$ env PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
----------------------------------------------------------------------
Ran 276 tests in 20.826s

OK

$ npx playwright test --reporter=dot --output=/tmp/adversaryflow-playwright-phase5-full
Running 71 tests using 2 workers
·······································································
71 passed (1.4m)

$ .venv/bin/ruff check .
All checks passed!

$ .venv/bin/mypy
Success: no issues found in 39 source files

$ node --check frontend/app.js && node --check tests/e2e/wizard.spec.js && node --check tests/e2e/uat.spec.js
# exit 0, no diagnostics
$ bash -n install.sh run.sh
# exit 0, no diagnostics
$ pwsh -NoProfile -Command '[System.Management.Automation.Language.Parser]::ParseFile(...)'
# exit 0, no diagnostics
```

The first sandboxed clean-install attempt could not resolve PyPI because the
execution sandbox disables network access. The same hash-pinned install was
rerun with network permission in an isolated `/tmp` checkout and exited 0:
both lock sets installed, the editable wheel built, `doctor` reported
`cache_writable = true`, `frontend_available = true`, and `ok = true`, then the
script printed `AdversaryFlow installed and verified. Start it with ./run.sh`.
This was an execution-environment restriction, not a product failure.

The live offline service run produced:

```text
[AdversaryFlow] starting; the browser will open when ATT&CK data is ready
AdversaryFlow 0.4.0: http://127.0.0.1:5057
health=ready ready=True phase=ready
cache_offline=True cache_exists=True cache_fresh=False
actors=232 contract_violations=0
APT29: techniques=66 curated=66 fallback=0 stages=13 commands_missing=0
actors=232 mapped=536 fallback=0 technique_keys=540 command_records=856
exercise_ids=146 scenario_families=25 receipts_valid=146 cleanup_verified=146
occupied_port_exit=1 error="OSError: [Errno 98] Address already in use"
alternate_port_live={"status":"live","version":"0.4.0"}
```

A downloaded Linux kit was then run from a terminal with a deliberately failing
step and a deliberately failing cleanup (J62):

```text
runner exit code: 0
evidence files: SHA256SUMS commands evidence-events.jsonl execution-report.html
                execution-report.md execution-results.csv execution-summary.json stdout stderr
summary: status=completed failed_steps=1 completed_steps=0
csv row: exit_code=3 execution_status=completed assessment=failed cleanup_status=failed
set -e statements in generated runner: 0
```

### Where each case runs

| Cases | Executor | Re-run by CI |
|---|---|---|
| J2, J3, J5–J9, J12, J16, J40–J53, J57–J59, J62, B39–B47, E1, E7–E10, E14, E16 | Python unit/integration suites | yes — `test` job |
| J10, J11, J13–J15, J17–J39, J55, J56, J60, J61, B1–B38, E3–E6, E11–E13, E15 | Playwright browser suites | yes — `browser` job |
| J1, J4, J52, J54, plus live-bundle runs of J5, J6, J9, J12, J16, J40, J41 | terminal against a running service and the cached real ATT&CK bundle | no — needs the 54 MB bundle and a bound port |
| `E2` | Two local service processes | no — requires binding the same real port twice |

### Manual re-run

```bash
./install.sh                                   # J1
ADVERSARYFLOW_CACHE_DIR="$PWD/data" ADVERSARYFLOW_OFFLINE=1 ./run.sh   # J4, J52
curl -s -D - http://127.0.0.1:5000/api/session -o /dev/null             # J6
curl -s http://127.0.0.1:5000/api/actors | head -c 200                  # J12
```
