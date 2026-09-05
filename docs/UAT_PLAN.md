# AdversaryFlow — User Acceptance Test Plan

Covers every row of the journey map in [USER_JOURNEY.md](USER_JOURNEY.md),
plus the boundary inputs the accepted behaviour depends on.

**Case IDs** — `J1`–`J55` are the journey-map rows. `B1`–`B33` are plan-import
boundaries. `B34`–`B42` are service and catalog boundaries.

**How to read the Steps column** — cases marked *(auto)* are executed by the
named test in the repository's own suites and are re-run by CI. Cases marked
*(manual)* were executed from a terminal against a live service and the real
ATT&CK enterprise bundle; their captured output is the Actual result.

## Environment of record

| Item | Value |
|---|---|
| Build | AdversaryFlow 0.3.0 |
| Python | 3.14.4 (CPython, Linux) |
| Node | v24.19.0, Playwright 1.62.1, Chromium |
| PowerShell | 7.6.5 (`Core`, Linux host) |
| ATT&CK data | `enterprise:bundle--6198013c-6f02-42a4-9713-38ea1301a1aa` (227 actors) |
| Service under test | `http://127.0.0.1:5055`, loopback, offline mode against the cached bundle |
| Suites | `pytest`, `npm run test:e2e`, Ruff, mypy, JavaScript/Bash/PowerShell syntax and launcher checks |

---

## A. Happy path — primary journey

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| J1 | Clean source checkout, Python ≥ 3.10 | `./install.sh` *(manual)* | stdout ends `AdversaryFlow installed and verified.`; exit 0 | From an isolated source archive with no `.venv`: installed both hash-locked sets, built the editable package, doctor reported `ok = true`, then printed `AdversaryFlow installed and verified. Start it with ./run.sh`; exit 0 | **Pass** |
| J2 | Installed | `adversaryflow --version` *(manual)*; `test_uat.py::test_j02_the_version_is_reported` *(auto)* | stdout exactly `AdversaryFlow 0.3.0` | `AdversaryFlow 0.3.0`; exit 0 | **Pass** |
| J3 | Installed | `adversaryflow doctor` *(manual)*; `test_j03_doctor_reports_a_healthy_install` *(auto)* | exit 0; `ok`, `frontend_available`, `cache_writable` all true | `ok = True, frontend_available = True, cache_writable = True, version = 0.3.0, deps = {Flask: 3.1.3, waitress: 3.0.2}`; exit 0 | **Pass** |
| J4 | Installed, cache seeded | `./run.sh` *(manual)* | stdout announces the service URL | `[AdversaryFlow] starting; the browser will open when ATT&CK data is ready` / `AdversaryFlow 0.3.0: http://127.0.0.1:5055` | **Pass** |
| J5 | Service running | `curl http://127.0.0.1:5055/` *(manual)*; `test_j05_the_wizard_page_is_served` *(auto)* | HTTP 200 with the wizard title | `HTTP 200`, `<title>AdversaryFlow — Adversary Emulation Planner</title>` | **Pass** |
| J6 | Service running | `curl -D - /api/session` *(manual)*; `test_j06_every_response_is_hardened` *(auto)* | nosniff, no-referrer, same-origin, request id, CSP with `frame-ancestors 'none'` | All five headers present; CSP contained `frame-ancestors 'none'`; request ID was non-empty | **Pass** |
| J7 | Service running | `test_j07_a_session_token_is_issued` *(auto)* | Non-empty `csrf_token` and `version` | Token issued; `version = 0.3.0` | **Pass** |
| J8 | Data not yet loaded | `test_j08_bootstrap_starts_and_reaches_ready` *(auto)* | POST 200/202, then `runtime.ready = true` | POST accepted; poll returned `ready = true` | **Pass** |
| J9 | Before / after load | `test_j09_health_is_degraded_before_data_is_ready`, `…_ready_once_data_is_loaded` *(auto)*; live curl *(manual)* | 503 `degraded`, then 200 `ready` | 503 `degraded`; live service `status = ready, ready = True, phase = ready, version = 0.3.0` | **Pass** |
| J10 | UI reachable | `uat.spec.js` J10 *(auto)* | Welcome heading and enabled start button | Heading, enabled button, and the "does not execute commands" footer all visible | **Pass** |
| J11 | Actors loaded | `uat.spec.js` J11 *(auto)* | `#dataStatus` matches `^\d+ actors? · Enterprise$` | Matched | **Pass** |
| J12 | Data loaded | `test_j12_actor_records_carry_the_published_contract` *(auto)*; live curl *(manual)* | Every actor carries the seven published fields; live count 227 | Contract violations = 0; `actors = 227`; `G0016 = APT29, technique_count = 66` | **Pass** |
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
| J29 | On step 4 | `uat.spec.js` J29 *(auto)* | JSON validates against the published schema | `AdversaryFlow_G0001_UAT_Actor.json` valid per Ajv 2020; outcome `passed`, note `Observed` round-tripped | **Pass** |
| J30 | On step 4 | `uat.spec.js` J30 *(auto)* | Markdown report with heading, technique, outcome, command | `# AdversaryFlow — UAT Actor (G0001)`, `### T1059.001 — PowerShell`, `**Outcome:** failed`, `**Detection:** not_assessed`, `whoami` | **Pass** |
| J31 | On step 4 | `uat.spec.js` J31 *(auto)* | Non-executable `.txt` runbook with every command commented | `AdversaryFlow_G0001_UAT_Actor_runbook.cmd.txt` contained `REM AdversaryFlow runbook`, `REM ===== 1. EXECUTION =====`, `REM Outcome: not_run`, `REM Detection: not_assessed`, and `REM COMMAND: whoami`; no line equalled `whoami` | **Pass** |
| J32 | A saved JSON plan exists | `uat.spec.js` J32 *(auto)* | Plan restored with evidence intact | Toast `Plan imported as high-risk…`; heading `UAT Actor · G0001`; outcome `passed`; note `Script block logging fired` | **Pass** |
| J54 | Real bundle and catalog available | Resolve every actor-mapped technique, inspect the exercise registry, and execute every bounded exercise *(manual plus `test_catalog.py` / `test_lab_exercises.py` auto)* | 0 mapped techniques use the runtime fallback; every one of the 146 bounded entries has a technique-relevant scenario and valid receipt | `actors=227 mapped=529 fallback=0`; `533` technique keys, `848` command records; `146` exercise IDs each available on Windows/Linux/macOS across `25` scenario families; all 146 passed, cleaned up, and produced a valid SHA-256 receipt | **Pass** |

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
| J40 | Service running | `GET /api/actors?domains=bogus` *(auto: `test_j40…`; manual curl)* | 400 with the standard envelope | `HTTP 400 {"error":"bad_request","message":"Unknown ATT&CK domain(s): bogus","version":"0.3.0"}` | **Pass** |
| J41 | Service running | `GET /api/workflow/intrusion-set--nope` *(auto: `test_j41…`; manual curl)* | 404 with error, message and version | `HTTP 404 {"error":"actor_not_found","message":"No ATT&CK group or campaign matches intrusion-set--nope in the selected domains.","version":"0.3.0"}` | **Pass** |
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
| J52 | Cache seeded, `--offline` | Serve and query the API *(manual)* | Served from cache with no upstream request | `offline = True`, `enterprise cached = True, fresh = True`; 227 actors served | **Pass** |
| J53 | Empty cache dir, `--offline` | `load_bundle("enterprise")` *(auto: `test_j53…`)* | Actionable error | `RuntimeError: offline mode requires a cached enterprise ATT&CK bundle at <path>` | **Pass** |
| J55 | UI reachable | axe-core scan of step 0 *(auto: `uat.spec.js` J55)* | No serious or critical violations | `[]` | **Pass** |

---

## C. Boundary inputs

### C.1 Plan import contract — executed in the loaded page against the shipped validator

*(auto: `uat.spec.js` "J34/J35 boundaries — the import contract holds at every documented limit")*

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
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
| B22 | Exactly 32 stages | Validate | Accepted | accepted | **Pass** |
| B23 | 33 stages | Validate | `Plan stage count is invalid` | as expected | **Pass** |
| B24 | Stage without a title | Validate | `Plan contains an invalid stage` | as expected | **Pass** |
| B25 | Technique without a name | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B26 | `platforms` not an array | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B27 | Invalid technique URL | Validate | `Plan contains an invalid technique record` | as expected | **Pass** |
| B28 | Command of exactly 10,000 characters | Validate | Accepted | accepted | **Pass** |
| B29 | Command of 10,001 characters | Validate | `Plan contains an invalid command record` | as expected | **Pass** |
| B30 | Command without a risk value | Validate | `Plan contains an invalid command record` | as expected | **Pass** |
| B31 | Invalid execution outcome | Validate | `Plan execution record is invalid` | as expected | **Pass** |
| B32 | Exactly 2,000 techniques | Validate | Accepted | accepted | **Pass** |
| B33 | 2,001 techniques | Validate | `Plan contains too many technique records` | as expected | **Pass** |

### C.2 Service and catalog boundaries

*(auto: `tests/test_uat.py::BoundaryUatTests`)*

| Test ID | Precondition | Steps | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| B34 | Service running | `GET /api/actors?domains=` | Falls back to `enterprise` | `["enterprise"]` | **Pass** |
| B35 | Service running | `GET /api/actors?domains=%20,%20` | Falls back to `enterprise` | `["enterprise"]` | **Pass** |
| B36 | Service running | `GET /api/actors?domains=enterprise,ics,mobile` | All three accepted in order | `["enterprise","ics","mobile"]` | **Pass** |
| B37 | Service running | `GET /api/actors?domains=enterprise,bogus` | One bad value rejects the request | HTTP 400 | **Pass** |
| B38 | Service running | `POST /api/refresh` with a 17,850-byte body (limit 16,384) | Rejected; unauthenticated before the body is read | No token → 403; with token → 413 `request_entity_too_large` | **Pass** |
| B39 | Service running | `POST /api/refresh` with a body under the limit | Accepted | HTTP 200 | **Pass** |
| B40 | Catalog loaded | `get_commands("T9999", …, ["execution"])` | Exactly one fallback command naming the technique | `source = fallback`, 1 command containing `T9999` | **Pass** |
| B41 | Catalog loaded | `get_commands("T9999", …, [])` | Still returns a runnable command | `source = fallback`, non-empty command | **Pass** |
| B42 | Catalog loaded | Inspect all 848 command records | Every risk is low/medium/high; medium and high require acknowledgement | All records conform | **Pass** |

---

## D. Cases requiring human judgment

These are **not** automated and were not claimed as passed. They need a person
with a lab and a detection platform.

| Area | Why it needs a human |
|---|---|
| Whether a copied command actually fires the operator's detection | Depends on the operator's EDR/SIEM, not on AdversaryFlow |
| Whether an exported Markdown report reads well for a given audience | Editorial judgment |
| Real browser-to-clipboard behaviour under a corporate policy | Environment-specific |
| Behaviour of a genuine first-run download on a metered or proxied network | Requires that network |

---

## E. Execution summary

Executed on the environment of record above.

| Group | Cases | Pass | Fail |
|---|---|---|---|
| A. Happy path (journey rows) | 28 | 28 | 0 |
| B. Alternate and error paths (journey rows) | 27 | 27 | 0 |
| C.1 Plan-import boundaries | 33 | 33 | 0 |
| C.2 Service and catalog boundaries | 9 | 9 | 0 |
| **Total** | **97** | **97** | **0** |

Every journey-map row `J1`–`J55` is covered exactly once across groups A and B.

### Suites executed

```text
$ python -m unittest discover
Ran 205 tests in 7.777s
OK

$ npm run test:e2e -- --reporter=dot
Running 48 tests using 2 workers
................................................
48 passed (1.1m)

$ ruff check .
All checks passed!

$ mypy backend
Success: no issues found in 35 source files

$ node --check frontend/app.js tests/e2e/wizard.spec.js tests/e2e/uat.spec.js
$ bash -n install.sh run.sh
$ pwsh -Command '[System.Management.Automation.Language.Parser]::ParseFile(...)'
# all syntax commands exited 0 with no diagnostics
```

The first sandboxed `./install.sh` invocation correctly exposed that the
sandbox could not write the normal user cache and exited 1 at `doctor`. The
same command was rerun with normal user-directory permissions; `cache_writable`,
`frontend_available`, and `ok` were all `true`, and installation exited 0. This
was an execution-environment restriction, not a product failure.

The live offline service run produced:

```text
[AdversaryFlow] starting; the browser will open when ATT&CK data is ready
AdversaryFlow 0.3.0: http://127.0.0.1:5055
health=ready ready=True phase=ready
actors=227 contract_violations=0
APT29: techniques=66 curated=66 fallback=0 stages=13 commands_missing=0
actors=227 mapped=529 fallback=0 technique_keys=533 command_records=848
exercise_ids=146 scenario_families=25 receipts_valid=146 cleanup_verified=146
```

### Where each case runs

| Cases | Executor | Re-run by CI |
|---|---|---|
| J2, J3, J5–J9, J12, J16, J40–J53, B34–B42 | `tests/test_uat.py`, `tests/test_catalog.py` | yes — `test` job |
| J10, J11, J13–J15, J17–J39, J55, B1–B33 | `tests/e2e/uat.spec.js` | yes — `browser` job |
| J1, J4, J52, J54, plus live-bundle runs of J5, J6, J9, J12, J16, J40, J41 | terminal against a running service and the cached real ATT&CK bundle | no — needs the 54 MB bundle and a bound port |

### Manual re-run

```bash
./install.sh                                   # J1
ADVERSARYFLOW_CACHE_DIR="$PWD/data" ADVERSARYFLOW_OFFLINE=1 ./run.sh   # J4, J52
curl -s -D - http://127.0.0.1:5000/api/session -o /dev/null             # J6
curl -s http://127.0.0.1:5000/api/actors | head -c 200                  # J12
```
