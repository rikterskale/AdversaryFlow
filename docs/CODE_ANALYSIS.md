# AdversaryFlow code analysis and verification

This review assesses the current planner, its browser workflow, persistence,
exports, installation artifacts, and live ATT&CK integration. Reliability and
user experience defects found during the review were corrected in the working
tree. The final local checks pass, with the environment limits recorded below.
This is evidence of tested behavior, not a guarantee that every future feed,
host configuration, or user action will succeed.

Reviewed on September 30, 2026, on Windows with Python 3.14. The corrections
and this report are committed together; this review did not publish a release
or deploy the application.

## Verification results

| Check | Result |
| --- | --- |
| Python test discovery | 385 collected; 381 passed and 4 skipped |
| Optional content pack tests | All 6 passed in an isolated environment with cryptography 50.0.1, including the 3 signature tests skipped by the default environment |
| TypeScript, production build, and Vitest | Passed; all 36 frontend tests passed |
| Chromium, Firefox, and WebKit | All 270 browser tests passed, 90 per engine |
| Ruff | No findings |
| Mypy | No findings across 60 Python source files |
| Installed Python dependency consistency | `pip check` passed |
| npm vulnerability audit | Zero reported vulnerabilities after the dependency correction |
| Python runtime vulnerability audit | No known vulnerabilities reported for the 8 dependencies in requirements.lock |
| Wheel and source distribution | Both built successfully with the pinned build tools |
| Distribution asset verification | Packaged frontend bytes and source rebuild inputs match the working tree |
| Isolated wheel installation | CLI version, all 4 static assets, live Enterprise actor listing, workflow, and readiness passed |
| Local Docker Compose startup | Fresh image build with an empty isolated cache passed; authenticated readiness reached and temporary test resources removed |
| Native macOS CI baseline | Safari, macOS Python 3.10/3.14, and packaged installation passed for baseline b9020504e52742af75622d3d501780e38d1943c7; verification of the review corrections requires CI for their commit |
| Official live ATT&CK data | Every actor workflow in Enterprise, ICS, and Mobile returned successfully; combined domain listing and readiness passed |

The default Python environment lacks the optional content pack extra, causing
three skips. Those exact signature cases were executed successfully in the
isolated environment. The remaining skip is the POSIX installer stub test,
which explicitly excludes Windows. Native Windows interpreter and execution
kit tests ran successfully.

Browser tests cover the guided journey, authentication and CSRF recovery,
saved evidence, data version changes, platform changes, denied storage and
clipboard access, malformed imports, failed feed refresh, report downloads,
server revision saves, keyboard navigation, accessibility, and mobile layouts.
The real Flask integration cases exercise the production backend against
isolated STIX fixtures. Live feed validation is a separate check using the
official downloaded bundles.

## Corrections made

| Problem | Resulting behavior |
| --- | --- |
| SQLite context managers did not close connections | Store operations now close handles deterministically, including early returns, exceptions, and failed connection setup. Tests retain connection references to prove closure independently of garbage collection. |
| API export tests wrote to the actual user database | Each API test now has a temporary database, preventing contamination of user records and dependence on user cache permissions. |
| A delayed engagement save could attach its ID to another plan | The browser applies the returned engagement identity only if the initiating actor, evidence identity, and existing engagement identity are still active. |
| CSV header aliases were unordered | Explicit technique columns consistently take precedence over generic row IDs. Other field aliases also have defined precedence. |
| Non-string STIX versions could raise an internal error | Invalid version fields produce an import validation error. |
| Invalid signed content enum fields could raise TypeError | Arrays and objects are rejected through the content pack validation contract. |
| Multi-tactic techniques produced duplicate Atomic definitions or gap rows | Atomic exports emit one definition or gap per technique, avoiding ambiguous duplicate ZIP paths. |
| Non-object JSON domain requests could produce an internal error | Requests receive a structured 400 validation response. |
| Native browser opening depended on data already being ready | The launcher can open the serving UI during preparation and with `--no-preload`, allowing the UI to initiate setup. |
| Invalid environment ports could produce tracebacks, and IPv6 URLs were malformed | Ports receive argument validation, IPv6 URLs use brackets, and diagnostics parse IPv6 hosts correctly. |
| Vite forwarded requests to an undocumented port | Its API proxy now matches the backend default, port 5000; CONTRIBUTING.md documents the two-terminal workflow. |
| fast-uri 3.1.7 had a reported moderate advisory | The lockfile now selects the compatible patched version, 3.1.8. The final audit reports zero vulnerabilities. |
| Catalog coverage wording did not distinguish ATT&CK domains | README.md now states that curated coverage applies to Enterprise, with generic desktop proxies for ICS and Mobile. |

New regression coverage includes immutable revisions, concurrent revision
allocation, rollback of failed saves, audit tamper detection, backlog ownership
preservation, webhook leases, optional signed pack verification, and server
engagement identity across browser reloads. Generated frontend assets were
rebuilt alongside their source changes.

## Live domain coverage

| Domain | Actor workflows checked | Distinct actor technique IDs | Technique IDs using fallback catalog entries |
| --- | --- | --- | --- |
| Enterprise | 232 | 536 | 0 |
| ICS | 20 | 57 | 57 |
| Mobile | 21 | 64 | 64 |

The combined view contains 238 actors because some actors occur in more than
one domain. All checked techniques returned command records. Enterprise has
curated coverage for every actor technique in the downloaded bundle, but an
individual command can still be withheld by the selected platform or guardrails.
Curated entries also include bounded synthetic exercises and lab proxies;
catalog coverage does not establish complete behavioral emulation or detection.

ICS and Mobile fallback entries are generic desktop lab proxies. The planner
does not implement Android, iOS, or industrial-device executors. Those mappings
remain useful for planning, but should not be interpreted as native device
emulation coverage.

## Boundaries reviewed

The service remains a planner and serializer. It generates operator-controlled
offline artifacts rather than executing catalog commands through HTTP. Export
tests verify catalog rebinding and guardrail enforcement, including refusal to
enable withheld steps or accept arbitrary client command text as trusted
execution content. Reports escape supplied text and exclude executable command
bodies from their human-readable formats.

API tests exercise bearer authentication for remote mode, same-origin checks,
CSRF token renewal, request limits, structured errors, response headers, and
request identifiers. Persistence tests verify transaction behavior and audit
integrity. Optional pack tests verify trusted signatures and reject altered
payloads and unexpected archive paths. Webhook persistence tests use a dummy
endpoint and perform no external delivery.

The data layer validates official STIX bundles, records provenance, and
supports cached and offline operation. Tests cover corruption, atomic cache
writes, failed refresh preservation, and domain index separation. The browser
partitions evidence by actor, platform, and data version and supports recovery
snapshots. Denied storage and clipboard operations are visible to the operator.

## Environment dependent checks

Docker Desktop's Linux engine was started on this host, and
`python scripts/compose_smoke.py --fresh` passed against the current working
tree. The check built a fresh image, downloaded ATT&CK data into an empty
isolated cache, waited for container health, verified authenticated readiness,
and removed its own temporary container, network, and cache volume. The local
result is recorded in `docker-local-fresh.log`.

Native macOS Safari and the macOS system Bash are not available on this Windows
host. GitHub CI provides those environments. The committed baseline
`b9020504e52742af75622d3d501780e38d1943c7` passed
[native Safari](https://github.com/rikterskale/AdversaryFlow/actions/runs/36607694646/job/109540835610),
macOS Python 3.10/3.14 tests, packaged installation, and
[Docker Compose](https://github.com/rikterskale/AdversaryFlow/actions/runs/36607694646/job/109540835531)
on September 29, 2026. Safari logs confirm authentication, evidence, HTML/JSON/PDF
exports, platform separation, resume, CSRF renewal, and token reconnect.

These CI results establish baseline behavior. Verification of the review
corrections requires a successful CI run for the commit containing them. The
existing workflow automatically runs native Safari and macOS test jobs on
pushes to main and on pull requests. Check the commit's GitHub Actions run for
the current result. A Mac is not required on the developer's workstation.

The existing global Firefox test executable failed to launch. A fresh official
Playwright runtime in the ignored audit directory passed all final Firefox
checks. This was a test environment issue, not a browser behavior failure in
the application.

No percentage of line or branch coverage was measured. The concurrency check
exercised eight revision saves across four workers; it is not a sustained load test.
Known-vulnerability audits describe the advisory databases at review time and
cannot rule out undisclosed vulnerabilities. Actual endpoint/SIEM detection and
third-party webhook delivery require the operator's own integrations and were
not established by local fixtures.

## Reproduce the checks

From the repository root on Windows:

```powershell
.venv/Scripts/python.exe -m unittest discover --verbose
.venv/Scripts/python.exe -m ruff check .
.venv/Scripts/python.exe -m mypy
npm run check:frontend
npx playwright install chromium firefox webkit
npm run test:e2e
npm audit
.venv/Scripts/python.exe -m build --no-isolation
.venv/Scripts/python.exe scripts/verify_distribution_assets.py
```

Install the hash-locked runtime, development, and build requirements first.
Run the signed content pack tests in an environment containing the project's
optional `content-packs` extra. The standard generated-asset freshness command
compares with Git, so source and regenerated assets must be committed together.

Local execution logs, vulnerability audit JSON, downloaded bundles, isolated
environments, and distribution artifacts are under
`.audit-cache/code-analysis/`. They are ignored by Git. The final browser log is
`browser-final.log`; Python and frontend results are `python-final.log` and
`frontend-final.log`. Live-domain results are `live-smoke.json`, and installed
wheel results are `wheel-smoke.json`.
