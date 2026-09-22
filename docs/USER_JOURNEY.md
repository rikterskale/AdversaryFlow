# AdversaryFlow — User Journey

> Every screen, command, message, and status code in this document was read out
> of the source and observed running. Where a number appears (technique counts,
> limits, timeouts) it was measured against the checked-in code or the live
> ATT&CK bundle, not estimated.

If you are installing or running AdversaryFlow for the first time, use
[Getting started](GETTING_STARTED.md). This page is the observed journey map
behind that handbook.

---

## 1. Product overview

AdversaryFlow turns a **named threat actor into an ordered development-lab
workflow**. You pick an adversary — APT29, FIN7, Lazarus, or a named campaign —
and AdversaryFlow resolves the techniques that actor is recorded as using in
the MITRE ATT&CK STIX feed, sorts them into the order published in the ATT&CK
matrix, and attaches a catalog record to each one. Some records contain direct
lab actions. Behaviours that would be unsafe or require external infrastructure
receive a bounded, technique-relevant exercise that uses synthetic data,
temporary artifacts, child processes, or ephemeral loopback services. These
exercises reproduce a safe observable surface of the technique, not the full
harmful attack or its real-world impact.

It is built for people who need to answer *"would we actually see this
adversary?"* and want an answer grounded in evidence rather than a coverage
spreadsheet. The audited catalog has **540 technique keys and 856 command
records**. The audited enterprise dataset mapped 536 unique techniques across
232 groups and campaigns, and those mapped techniques resolve to catalog
records rather than the runtime fallback. This is coverage of catalog records,
not proof of full attack-behaviour fidelity: **146 catalog techniques are
explicitly marked bounded synthetic exercises** and mapped to 25
technique-relevant scenario families. Each emits a self-reported JSON receipt
with a unique run ID, timestamps, scenario events, exit code, cleanup result,
and SHA-256 digest. Receipt integrity proves what the runner reported; endpoint
or SIEM correlation is required for independent execution proof. Every record carries
structured safety metadata — risk rating,
whether it needs administrator rights or network access, what it changes, the
telemetry you should expect, and how to undo it — and the interface refuses to
hand you a command whose risk exceeds the scope you set.

The AdversaryFlow web service **generates plans; it never executes commands**.
It runs entirely on your own machine, binds to loopback by default, and stores nothing beyond a
cached copy of the public ATT&CK bundle and your own progress in browser local
storage. The finished plan exports as a one-click, offline operator kit with a
CSV and standalone PowerShell/Bash runner, as a command-free HTML or PDF
engagement report, or as Markdown, schema-versioned JSON, and a commented text
runbook. A JSON export can be loaded back in later to resume exactly where you
left off.

---

## 2. Personas

| Persona | Goal | Entry point |
|---|---|---|
| **Detection engineer** — owns EDR/SIEM rules and needs evidence about a specific adversary | Review one actor's mapped exercises, run suitable commands in a lab, and record which detections fired | `./run.sh` → browser opens at `http://127.0.0.1:5000` |
| **Purple-team lead** — plans and reports on a scheduled exercise | Scope an exercise to a platform and a set of kill-chain stages, then hand the team a runbook and keep an evidence record | Welcome screen → **Begin emulation plan** → **Export** |
| **Returning operator** — picked up a half-finished exercise, or received one from a colleague | Restore a previous plan with its outcomes and evidence notes intact | Welcome screen → **Resume saved plan** or **Resume JSON plan** |
| **Automation / platform engineer** — feeds plans into other tooling | Pull the workflow as JSON without touching the UI | `curl http://127.0.0.1:5000/api/workflow/<stix_id>` |
| **Lab operator** — runs the service for a team, or on an air-gapped host | Keep the service healthy, control where ATT&CK data comes from, and gate remote access | `adversaryflow doctor`, `cache-status`, `--offline`, `--allow-remote --api-token` |

---

## 3. Primary journey

The path from an empty checkout to a delivered, exported emulation plan.

### Step 1 — Install

```bash
./install.sh
```

`install.sh` verifies `python3` is present and is 3.10 or newer, creates
`.venv`, installs the hash-pinned runtime and build sets, installs the project,
then runs its own diagnostic.

**Observable result:** the script prints the `doctor` JSON report, then:

```
AdversaryFlow installed and verified. Start it with ./run.sh
```

Windows uses `.\install.ps1`, which performs the same checks via `py -3`.
Each native PowerShell step is checked explicitly: virtual-environment
creation, both pinned dependency installs, the editable package install, and
`doctor` stop immediately with a step-specific error if the child process
returns a non-zero exit code. The success message is therefore never printed
after a failed native command.

The package declares an `adversaryflow` console script. In a verified source
installation, `adversaryflow --version` prints `AdversaryFlow 0.5.1`.

### Step 2 — Launch

```bash
./run.sh
```

`run.sh` runs `install.sh` first if `.venv/bin/adversaryflow` is missing
(printing `[AdversaryFlow] first-run installation…`), then starts the service
with `--open`.

**Observable result:**

```
[AdversaryFlow] starting; the browser will open when ATT&CK data is ready
AdversaryFlow 0.5.1: http://127.0.0.1:5000
```

The HTTP service accepts requests immediately; ATT&CK data loads in a
background thread. The browser opens once the data is ready or has failed.

### Step 3 — First-run ATT&CK data preparation

The page loads and fetches `GET /api/session` for a same-origin token, then
polls `GET /api/bootstrap`. On a cold cache the first `GET` returns **503**, the
page issues `POST /api/bootstrap` with the `X-AdversaryFlow-CSRF` header, and
the background worker downloads the enterprise bundle.

**Observable result:** a full-screen loader reads

> **Preparing MITRE ATT&CK data…**
> The first run downloads and validates the enterprise bundle. Downloaded
> *N.N* MB of *N.N* MB. You can leave this tab open.

The byte values are calculated from live cache metadata and only appear once
download progress is available. The download is capped
at 128 MiB, checksummed, validated as a STIX bundle, and atomically promoted
before it is used. Subsequent launches reuse the disk cache for 7 days.

### Step 4 — Welcome screen

**Observable result:** the heading *"Turn a threat actor into an end-to-end
emulation plan"*, a **Begin emulation plan** button, a **Resume JSON plan**
button, and the footer *"Built for disposable development labs.
AdversaryFlow creates plans; it does not execute commands."* If this browser
already has an in-progress plan, **Resume saved plan** is also shown with the actor name.
The header status chip turns green and reads `<count> actors · Enterprise`.
The **?** control opens in-app help. If ATT&CK setup failed, a banner on every
screen reads the failure and offers **Retry setup**.

### Step 5 — Choose a threat actor

Click **Begin emulation plan** → screen *"Choose a threat actor"*.

You can search by name, alias, or ATT&CK ID; filter by **All / Groups /
Campaigns**; sort by **Name (A–Z)** or **Most techniques**; and switch or combine the
**Enterprise / ICS-OT / Mobile** domains. The gallery lists every mapped
group and campaign in the selected domains. There is no prescribed first
actor.

**Observable result:** each card shows the actor name, ATT&CK ID, a
`group`/`campaign` tag, aliases, a one-line description, and a technique count.
Selecting one marks it `Selected` and the footer bar reads
**`Selected: <name>`**. **Continue** becomes enabled.

### Step 6 — Scope the engagement

Click **Continue** → `GET /api/workflow/<stix_id>` → screen *"Scope the
engagement"*.

| Control | Effect |
|---|---|
| **Command platform** — Windows / Linux / macOS | Selects commands for that OS exactly; no cross-OS substitution ever happens. A fresh visit pre-selects this browser's OS. |
| **Execution record** — Operator, Target | Optional context stamped onto every evidence record and export |
| **Kill-chain stages** | Per-tactic chips with technique counts, plus **Select all** / **Clear all** |
| **Include pre-compromise tactics** | Keeps or drops Reconnaissance and Resource Development |
| **Curated tests only** | Hides any auto-generated fallback command |
| **Allow network-active commands** | Unblocks commands that contact a host |
| **Allow administrator commands** | Unblocks commands needing elevation |
| **Allow high-risk commands** | Unblocks commands with disruptive or sensitive side effects |

**Observable result:** the **Plan preview** card updates live — Actor,
Techniques, *Runnable on Windows*, Unsupported, Kill-chain stages, Command
target, and a curated/fallback split bar. The footer reads
`<runnable> runnable · <unsupported> unsupported across <stages> stages`.

### Step 7 — Build and walk the plan

Click **Build plan** → the *Emulation plan* screen, headed
`APT29 · G0016` with the subtitle *"development-lab emulation plan · commands
target **Windows**"* (or Linux / macOS). The plan opens on the first stage
that has a low-risk, copyable **lab proxy** or **direct** command — skipping
bounded-synthetic-only stages such as Resource Development — and marks that
card **Try this first**, with copyable tests listed before unsupported ones.

A left rail lists every stage in kill-chain order with a colour-coded number.
Each technique card shows:

- the ATT&CK ID as a link to attack.mitre.org, the technique name, and a
  `sub-technique` tag where applicable;
- a **safety block**: a risk badge (`low risk` / `medium risk` / `high risk`),
  plus `admin`, `network`, and `cleanup required` badges where they apply,
  the classified **Effects**, the **Expected** telemetry, **Prerequisites**,
  **Expected output**, **Timeout**, **Rollback**, and any **Network targets**;
- the **Lab command** for the selected platform, a fidelity badge
  (`direct`, `bounded synthetic`, or `lab proxy`), an operational note, and any cleanup command;
- an **evidence row** with separate **Command** (Not run / Ran / Failed /
  Skipped) and **Detection** (Not assessed / Alerted / Silent / Blocked /
  Not instrumented) selects, a note, cleanup status, and expandable
  **Execution proof** (run ID, ISO timestamps, exit code, stdout/stderr hashes,
  evidence source, and endpoint/SIEM references). Bounded exercise receipts can
  be pasted, SHA-256 verified, and imported without collapsing the card.
  `j` / `k` move the focused card and `c` copies its command. A chip under the
  progress ring reads **Saved in this browser**.

The source badge `curated` means the technique ID has a keyed catalog record;
it does not certify full ATT&CK-behaviour reproduction. Each bounded synthetic
entry invokes its registered scenario and reports scenario-specific expected
telemetry. For example, T1110 makes five rejected synthetic-credential requests
to an ephemeral loopback authentication service, while T1090.003 relays a
marker through two loopback hops. The digest protects the receipt from unnoticed
editing; only endpoint or SIEM correlation independently proves execution.

**Previous stage** / **Next stage** buttons and the rail both navigate.

### Step 8 — Copy a command and run it in your lab

Click **Copy command**. Any command classified medium or high risk first
raises an in-app confirmation that shows the command:

> Copy this high risk lab command?
> Review prerequisites, side effects, and cleanup before copying.
> AdversaryFlow does not execute the command.

**Observable result:** the button flips to **Copied** and a toast reads
*"Command copied to clipboard"*. You run the command yourself, in your own
disposable lab — AdversaryFlow never executes it.

### Step 9 — Record what happened

Set the command result, set the detection result, type an evidence note, and
tick **cleanup verified**. Changing those fields does not rebuild the stage or
clear other evidence on the card.

**Observable result:** the progress ring and the `N / M` counter update
immediately, the stage rail shows `done/runnable` counts (and a check when a
stage is complete), the save chip stays on **Saved in this browser**, and the
state is written to browser local storage under a key derived from the actor,
ATT&CK data version, domains, and command platform. Reloading the tab offers
**Resume saved plan** on the welcome screen, labelled with the actor name.

### Step 10 — Export

Click **Finish & export** → *"Your emulation plan is ready"*, with stat tiles
for **Techniques**, **Stages**, **Runnable tests**, and **Marked run**.

| Card | File | Contents |
|---|---|---|
| **Download Windows execution kit** | `AdversaryFlow_G0016_APT29_Windows.zip` | Catalog-rebound CSV plus standalone PowerShell runner; Linux and macOS plans receive Bash. Bounded synthetic steps also include `AdversaryFlow-exercises.py` (Python 3.10+). Direct steps need no AdversaryFlow installation or network connection. |
| **Generate report** | Preview in the Export step | Empty → generating → ready, or an actionable error with retry; the ready state embeds the self-contained HTML in a sandboxed preview |
| **PDF** | `AdversaryFlow_G0016_APT29_report.pdf` | Command-free, leadership-ready coverage, telemetry, detection mappings, evidence, and categorized gaps, rendered from the preview HTML |
| **HTML** | `AdversaryFlow_G0016_APT29_report.html` | The same self-contained, responsive document shown in the preview |
| **JSON** | `AdversaryFlow_G0016_APT29.json` | Canonical schema 2.0 plan validating against `schemas/adversaryflow-plan.schema.json`; this is the file you resume later |
| **Markdown report** | `AdversaryFlow_G0016_APT29.md` | Human-readable plan with outcomes, evidence, commands, notes, cleanup |
| **Commented runbook** | `AdversaryFlow_G0016_APT29_runbook.cmd.txt` | Review-only sequenced text with every metadata, command, and cleanup line commented (`REM` on Windows, `#` on Linux/macOS) |

The runbook remains a deliberately non-executable review format. The execution
kit is the controlled runnable handoff: each step requires an operator decision,
edited commands require a reason and second approval, and the destination runner
writes HTML/Markdown reports plus CSV, JSON, JSONL, logs, and checksums.
The service rebinds report content to the curated catalog before rendering the
HTML and PDF engagement reports. Those reports never contain runnable commands.
The JSON download preserves the submitted schema 2.0 record rather than
creating a second report schema.

**Observable result:** report generation moves from **Generating report
preview…** to **Preview ready** and the toast reads *"Engagement report preview
ready"*. The HTML, PDF, and JSON download controls then become available.
**Core value is delivered here.**

### Step 11 — Resume later

From the welcome screen choose **Resume JSON plan** and pick a previously
exported JSON file.

**Observable result:** the plan reopens directly on the *Emulation plan*
screen with its stages, outcomes, evidence notes, and operator/target context
restored, and a toast reads *"Plan imported as high-risk; verify its data
version before execution"*. Every imported command is re-classified as high
risk and requires acknowledgement before it can be copied, because its contents
came from a file rather than from the ATT&CK catalog.

The importer accepts only a bounded schema 2.0 document: 1–32 non-empty
stages, at most 2,000 techniques in any one stage, at most 4,000 technique
records across the plan, ATT&CK-formatted technique IDs, and commands no longer
than 10,000 characters. Runbook export treats all imported text as data: line
breaks in stage titles, technique names, notes, commands, or cleanup text are
normalized so every physical runbook line retains the platform's comment
prefix.

---

## 4. Alternate and error paths

### Install and launch

| Situation | What the user sees | Recovery |
|---|---|---|
| Python missing or older than 3.10 | `AdversaryFlow requires Python 3.10 or newer.` (or `…; found Python 3.9.18.`) on stderr, exit 1 | Install Python 3.10+ and re-run `./install.sh` |
| A native step in `.\install.ps1` fails | A step-specific terminating error names virtual-environment creation, runtime dependencies, build dependencies, package installation, or `doctor`; the success message is not printed | Correct the reported Python/package problem and re-run `.\install.ps1` |
| Port already in use | `waitress` fails to bind | `adversaryflow --port 5050 --open` |
| Non-loopback bind without opt-in | `Refusing a non-loopback bind without --allow-remote. Read docs/OPERATIONS.md first.` exit 2 | Add `--allow-remote` **and** a token |
| `--allow-remote` with no token | `Refusing a non-loopback bind without --api-token or ADVERSARYFLOW_API_TOKEN.` exit 2 | Supply `--api-token` or the environment variable |
| Remote mode active | `WARNING: remote binding is enabled; every API request requires the configured bearer token.` | Expected; the in-app connection dialog requests the token and holds it only in session storage |

### ATT&CK data

| Situation | What the user sees | Recovery |
|---|---|---|
| Setup fails (unreadable cache, network failure) | Status chip `setup needs attention`; a banner shows the error message and a **Retry setup** button on every screen | Click **Retry setup** |
| Bootstrap cannot be started (401/403) | The loader stops and the failure message is shown, rather than spinning forever | Reload; check the token in remote mode |
| Bootstrap never completes | After 15 minutes: *"Preparing ATT&CK data timed out. Check the service log, then retry setup."* | Inspect the JSON service log, then **Retry setup** |
| Backend unreachable mid-session | Status chip `setup needs attention` and the error panel contains the backend message | Restart the service, click **Retry setup** |
| Download exceeds 128 MiB or is not a STIX bundle | The partial file is discarded; the cache is never replaced | Retry, or `adversaryflow cache-clear --yes` |
| Refresh fails but a cache exists | The stale bundle is served and marked `stale` with the refresh error in `cache-status` | Reconnect and refresh |
| Cached bundle is corrupt (online) | Repaired automatically by an unconditional re-download | None needed |
| Cached bundle is corrupt (offline) | `cached enterprise ATT&CK bundle is invalid; reconnect and refresh or clear <path>` | Reconnect, or point `--cache-dir` at a good cache |
| Offline with no cache | `offline mode requires a cached enterprise ATT&CK bundle at <path>` | Seed the cache online first |

### Working in the UI

| Situation | What the user sees | Recovery |
|---|---|---|
| Search matches nothing | `No actors match your search.` | Clear the search with the ✕ button |
| Last ATT&CK domain deselected | Toast *"Keep at least one ATT&CK domain selected"*; the domain stays on | Select a different domain first |
| No technique has a command for the chosen OS | Card reads `No Linux test is available for this technique.` with the note *"Choose another platform or contribute an exact-platform test."*; **Build plan** is disabled | Switch platform, or contribute a test |
| A command exceeds the scope you set | Card reads `Restricted by scope: high-risk commands are disabled.` with *"Enable the corresponding safety option in Scope after reviewing the risk."*; both **Copy command** and **Copy cleanup** are disabled | Enable the matching option in Scope |
| All stages deselected | Footer reads `No techniques in scope — enable a stage`; **Build plan** disabled | Click **Select all** |
| Clipboard blocked by the browser | Toast *"Clipboard access was denied"* | Select the command text manually |
| Local storage unavailable (private mode, quota) | Toast *"Progress can't be saved in this browser — export the plan to keep your records"*, shown once | Export the JSON plan to preserve records |
| Operator execution kit generation fails | A toast shows the API's error message, or `Execution kit could not be generated (<status>)` when no JSON message is available; the export button is restored | Correct the reported plan/session problem and click the execution-kit card again |
| Engagement report generation fails | The preview area shows **Report generation failed**, preserves the API message, and offers **Retry report generation**; the same message also appears in a toast | Correct the reported plan/session problem and retry generation |
| PDF/JSON report download fails after preview | The preview remains visible, an inline error and toast show the API message, and all download controls are restored | Correct the reported service/session problem and retry the format |
| Refresh while a plan is open | Confirm dialog *"Refreshing can change technique mappings and will rebuild the current plan. Continue?"*; on success, toast *"ATT&CK feed refreshed; the plan was rebuilt"* | Cancel to keep the current plan |
| Refresh twice within 5 seconds | `429 refresh_rate_limited` | Wait a few seconds |
| Refresh while another refresh or bootstrap runs | `409 refresh_in_progress` / `409 bootstrap_in_progress` | Wait for it to finish |

### Resuming a plan

Every rejection leaves the welcome screen intact and usable; nothing is
half-imported.

| Rejected because | Toast |
|---|---|
| File larger than 5 MB | `Plan file is larger than 5 MB` |
| Not a schema 2.0 export | `This is not an AdversaryFlow 2.0 plan export` |
| Missing tool/data version | `Plan is missing its tool or ATT&CK data version` |
| Actor record incomplete | `Plan actor record is invalid` |
| Unknown ATT&CK domain | `Plan contains an invalid ATT&CK domain` |
| Bad platform or safety flags | `Plan scope is invalid` |
| Bad operator/target block | `Plan execution context is invalid` |
| Zero stages, or more than 32 stages | `Plan stage count is invalid` |
| Empty or malformed stage | `Plan contains an invalid stage` |
| Malformed technique or non-ATT&CK technique ID | `Plan contains an invalid technique record` |
| Missing command, or command over 10 000 characters | `Plan contains an invalid command record` |
| More than 2 000 techniques in one stage | `Plan contains too many technique records` |
| More than 4 000 technique records across all stages | `Plan exceeds the 4000-technique limit` |

### Operator execution kit, on the destination host

The kit runs on the lab machine after the handoff, with no AdversaryFlow
installation and no network. A lab step that fails is an expected outcome and is
recorded as evidence — the runner never aborts the session on a non-zero exit,
so the summary, results CSV, event log, and checksums are always written.

| Situation | What the operator sees | Recovery |
|---|---|---|
| The plan CSV was edited or is missing | `Plan integrity check failed. The CSV does not match this runner.` (or `The matching plan CSV is missing: <path>`), exit 2 | Re-download the kit; keep the CSV and runner together |
| A required standard utility is absent | `Required standard utility not found: <name>` (or `sha256sum or shasum`), exit 2 | Install the named utility, or run the kit on a host that has it |
| A lab step exits non-zero | The exit code is printed and recorded; the session continues to the next step | None needed — the failure is the finding; `failed_steps` counts it in the summary |
| A step exceeds its timeout | Exit code `124` recorded with `execution_status = timed_out` | Raise the step timeout or shorten the command |
| A cleanup command fails | `cleanup_status = failed` recorded with its exit code | Reverse the change manually; the rollback text is in the CSV |
| The operator edits a command | A reason is required and the edited command needs a second approval; both original and effective SHA-256 are recorded | Skip or abort instead if the edit is wrong |
| The operator interrupts the session | `Execution interrupted. Evidence retained in: <dir>`, exit 130 | Evidence already written is kept and checksummed |

### API consumers

Every response carries `X-Request-ID`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`,
and a `Content-Security-Policy` including `frame-ancestors 'none'`. Errors use
one envelope: `{"error", "message", "version"}`.

| Call | Failure | Response |
|---|---|---|
| `GET /api/actors?domains=bogus` | Unknown domain | `400 {"error":"bad_request","message":"Unknown ATT&CK domain(s): bogus",…}` |
| `GET /api/actors` while loading | Data not ready | `503 service_unavailable` |
| `GET /api/workflow/<unknown>` | No such actor | `404 {"error":"actor_not_found","message":"No ATT&CK group or campaign matches … in the selected domains.",…}` |
| `POST /api/refresh` without the token | Missing CSRF header | `403 forbidden` |
| Mutating request with a correct token but a foreign, opaque, wrong-scheme, or wrong-port `Origin` | Origin does not exactly match scheme, host, and effective port | `403 forbidden`; matching IPv4/hostname/IPv6 origins continue normally |
| Any `/api/*` in remote mode without a bearer token | Unauthorised | `401 unauthorized` |
| `GET /api/health` before data is ready | Degraded | `503` with `status: "degraded"` and the failure phase |

### Diagnostics

| Command | Purpose | Result |
|---|---|---|
| `adversaryflow --version` | Identify the build | `AdversaryFlow 0.5.1` |
| `adversaryflow doctor` | Check Python and Docker/Compose versions, service port, frontend/runtime dependencies, cache integrity and writability, disk capacity, and ATT&CK feed reachability | PASS/FAIL JSON with a human-readable fix for each check; exit 0 healthy, exit 1 otherwise |
| `adversaryflow cache-status` | Inspect cache provenance per domain | JSON with path, age, freshness, ETag, SHA-256 |
| `adversaryflow cache-refresh --domains enterprise` | Force a re-download | Prints refreshed cache status |
| `adversaryflow cache-clear --yes` | Remove only AdversaryFlow cache files | `{"removed": [...]}`; without `--yes`: `Refusing to clear the cache without --yes.` exit 2 |

---

## 5. Journey map

Every success criterion below is binary and observable. Phase 5 consumes this
table directly.

| ID | Step | User action | System response | Success criterion |
|---|---|---|---|---|
| J1 | Install | `./install.sh` | Verifies Python ≥ 3.10, builds `.venv`, installs pinned sets, runs `doctor` | stdout contains `AdversaryFlow installed and verified.` and exit code is 0 |
| J2 | Verify install | `adversaryflow --version` | Prints the packaged version | stdout is exactly `AdversaryFlow 0.5.1` |
| J3 | Diagnose | `adversaryflow doctor` | Emits the host self-test used by the GUI health panel | Exit code 0 and `"ok": true`; every Python, Docker/Compose, port, dependency, cache, disk, and ATT&CK reachability check has PASS/FAIL state plus a human-readable fix |
| J4 | Launch | `./run.sh` | Starts waitress on loopback and opens a browser when ready | stdout contains `AdversaryFlow 0.5.1: http://127.0.0.1:5000` |
| J5 | Serve UI | `GET /` | Returns the wizard page | HTTP 200 and body contains `AdversaryFlow — Adversary Emulation Planner` |
| J6 | Harden responses | Any HTTP request | Security headers applied | Response has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`, a non-empty `X-Request-ID`, and a CSP containing `frame-ancestors 'none'` |
| J7 | Get a session token | `GET /api/session` | Issues a CSRF token | HTTP 200 and body has non-empty `csrf_token` and `version` |
| J8 | Prepare data | `POST /api/bootstrap` with `X-AdversaryFlow-CSRF` | Starts the background loader | HTTP 200 or 202; a later `GET /api/bootstrap` reports `runtime.ready = true` |
| J9 | Report readiness | `GET /api/health` | Reports readiness and provenance | HTTP 200 with `"status":"ready"` once loaded; HTTP 503 with `"status":"degraded"` before |
| J10 | Welcome screen | Open `http://127.0.0.1:5000` | Renders step 0 | Heading *Turn a threat actor…* visible and **Begin emulation plan** is enabled |
| J11 | Data status | Wait for load | Status chip updates | `#dataStatus` matches `^\d+ actors? · Enterprise$` |
| J12 | List actors | `GET /api/actors` | Returns mapped actors | HTTP 200; every entry has `stix_id`, `attack_id`, `name`, `type`, `aliases`, `description`, `technique_count`; the live enterprise catalog includes every non-deprecated group and campaign ATT&CK maps to techniques (directly or via software they use), while revoked/deprecated actors, relationships, software, and techniques are omitted |
| J13 | Choose an actor | Click **Begin emulation plan**, then an actor card | Selects it | Footer reads `Selected: <name>` and **Continue** is enabled |
| J14 | Search | Type `APT29` in the search box | Filters the grid | Only matching cards remain; the ✕ clear button appears |
| J15 | Empty search | Type a string matching nothing | Shows the empty state | `No actors match your search.` is visible |
| J16 | Build a workflow | `GET /api/workflow/<stix_id>` | Returns the ordered workflow | HTTP 200; top-level keys are exactly `actor`, `summary`, `kill_chain`, `stages`, `metadata`; stages follow `kill_chain`, and each technique contains `commands` and `command_source` |
| J17 | Scope screen | Click **Continue** | Renders step 2 | Heading *Scope the engagement* visible and footer reads `<n> runnable · <m> unsupported across <s> stages` |
| J18 | Switch platform | Click **Linux** | Re-selects commands for Linux only, never substituting another OS | Preview shows `Runnable on Linux`; techniques without a Linux command read `No Linux test is available for this technique.` |
| J19 | Toggle stages | Click **Clear all** | Empties the plan | Footer reads `No techniques in scope — enable a stage`, **Build plan** is disabled, and the button label becomes `Select all` |
| J20 | Safety scope | Leave *Allow high-risk commands* off with a high-risk command in scope | Blocks the command | Command text reads `Restricted by scope: high-risk commands are disabled.`; **Copy command** and **Copy cleanup** are both disabled |
| J21 | Unblock safety scope | Enable the matching option | Restores the command | Real command text is shown and the footer runnable count increases |
| J22 | Build the plan | Click **Build plan** | Renders step 3 | Heading reads `<name> · <attack_id>`; the plan opens on the first low-risk lab-proxy/direct command (marked **Try this first**); every in-scope stage appears in the rail and every technique card shows either the exact-platform command or an explicit unsupported message |
| J23 | Command safety metadata | Inspect any curated card | Shows the classification | A risk badge, **Effects**, **Expected** telemetry, ATT&CK detection text, and data-source chips are visible on every supported command |
| J24 | Navigate stages | Click **Next stage** / **Previous stage** / a rail item | Moves through the kill chain | The stage title changes; **Previous stage** is disabled on the first stage and **Next stage** on the last |
| J25 | Copy a command | Click **Copy command** | Copies after acknowledgement for medium/high risk | For a high-risk command an in-app dialog titled *Copy this high risk lab command?* shows the command; on **Copy command** the toast reads `Command copied to clipboard` |
| J26 | Record evidence | Set an outcome and expand **Execution proof** | Persists the note, cleanup state, run ID, timestamps, exit code, output hashes, evidence source, and telemetry references | `#progressCount` and `#progressPct` update to match the marked techniques; bounded-exercise receipts can be digest-verified and imported |
| J27 | Persistence failure | Make local storage throw | Warns instead of silently dropping records | Toast reads `Progress can't be saved in this browser — export the plan to keep your records` |
| J28 | Export screen | Click **Finish & export** | Renders step 4 | Heading *Your emulation plan is ready* with tiles Techniques, Stages, Runnable tests, Marked run |
| J29 | Export JSON | Click **Generate report**, then **JSON** | Downloads the canonical schema 2.0 plan | File named `AdversaryFlow_<ID>_<Name>.json` validates against `schemas/adversaryflow-plan.schema.json` |
| J30 | Export Markdown | Click **Markdown report** | Downloads a report | File named `AdversaryFlow_<ID>_<Name>.md` containing `# AdversaryFlow — <name> (<id>)`, a `### <technique>` section, and `**Outcome:**` |
| J31 | Export runbook | Click **Commented runbook**, including after importing fields containing line breaks | Downloads a non-executable review artifact | File named `AdversaryFlow_<ID>_<Name>_runbook.cmd.txt` containing `REM AdversaryFlow runbook`, `REM ===== 1. <STAGE> =====`, `REM Outcome:`, and `REM COMMAND:`; every physical metadata, command, and cleanup line retains `REM` on Windows or `#` on Linux/macOS |
| J32 | Resume a plan | **Resume JSON plan** → a valid export | Restores the plan | Lands on step 3 with the actor heading, outcomes, and evidence notes restored; toast reads `Plan imported as high-risk; verify its data version before execution` |
| J33 | Round-trip | Export with default scope, then resume that file | The plan is usable, not blocked by its own risk elevation | Command text is the real command (not `Restricted by scope`) and the runnable count is greater than 0 |
| J34 | Reject a bad plan | Resume a file with an incomplete actor | Refuses and stays put | Toast reads `Plan actor record is invalid` and the welcome screen is still displayed |
| J35 | Reject a foreign plan | Resume a file with `schema_version` ≠ `2.0` | Refuses | Toast reads `This is not an AdversaryFlow 2.0 plan export` |
| J36 | Plan another actor | Click **Plan another actor**, then **Begin emulation plan** | Resets the session and returns to the welcome screen | Domain filter is Enterprise only, type filter All, sort Name (A–Z), and the footer reads `Select a threat actor to continue` |
| J37 | Fresh actor context | Select a different actor | Starts with a clean record | Operator and Target fields are empty |
| J38 | Setup failure | Break `GET /api/session` | Surfaces an actionable error | Status chip reads `setup needs attention`, the failure message is shown in the setup banner, and a **Retry setup** button appears |
| J39 | Retry setup | Click **Retry setup** after the fault clears | Recovers without a reload | The actor grid renders and the status chip returns to `<n> actors · Enterprise` |
| J40 | Reject an unknown domain | `GET /api/actors?domains=bogus` | Rejects with the standard envelope | HTTP 400 with `error = bad_request` and a message naming `bogus` |
| J41 | Reject an unknown actor | `GET /api/workflow/intrusion-set--nope` | Rejects with the standard envelope | HTTP 404 with `error = actor_not_found` plus `message` and `version` |
| J42 | Require CSRF | `POST /api/refresh` with no token | Refuses | HTTP 403 with `error = forbidden` |
| J43 | Refresh recovery | `POST /api/refresh?domains=bogus`, then a valid refresh | The rejected call does not wedge the endpoint | First call 400; the refresh lock is released; a subsequent valid refresh is not 409 |
| J44 | Rate-limit refresh | Two valid refreshes within 5 s | Throttles the second | Second call is HTTP 429 with `error = refresh_rate_limited` |
| J45 | Reject remote access | Start with `--host 0.0.0.0` and no opt-in | Refuses to start | Exit code 2 and stdout contains `Refusing a non-loopback bind without --allow-remote.` |
| J46 | Require a remote token | `--host 0.0.0.0 --allow-remote` with no token | Refuses to start | Exit code 2 and stdout contains `Refusing a non-loopback bind without --api-token` |
| J47 | Enforce the bearer token | Remote mode, `GET /api/session` without `Authorization` | Refuses | HTTP 401; the same call with `Authorization: Bearer <token>` returns 200 |
| J48 | Inspect the cache | `adversaryflow cache-status` | Reports per-domain provenance | Exit 0; JSON lists `enterprise`, `ics`, `mobile` with `path`, `exists`, `fresh` |
| J49 | Guard cache deletion | `adversaryflow cache-clear` without `--yes` | Refuses | Exit code 2 and stdout contains `Refusing to clear the cache without --yes.` |
| J50 | Clear the cache safely | `adversaryflow cache-clear --yes` | Removes only AdversaryFlow files | Exit 0; `removed` lists only `*-attack.json` / `*-attack.meta.json`; unrelated files in the directory survive |
| J51 | Reject an unknown CLI domain | `adversaryflow cache-refresh --domains bogus` | Refuses | Exit code 2 and stdout contains `Unknown ATT&CK domain(s): bogus` |
| J52 | Operate offline | `adversaryflow --offline` with a seeded cache | Serves without network access | Actors load and no upstream request is made |
| J53 | Offline with no cache | `--offline` against an empty cache directory | Fails with an actionable message | Error contains `offline mode requires a cached enterprise ATT&CK bundle at` |
| J54 | Catalog coverage and disclosure | Resolve every technique used by the audited enterprise actors and inspect every catalog record | Every mapped technique resolves, while bounded exercises remain explicitly distinguishable from direct records | 536 unique actor-mapped techniques resolve with 0 runtime fallbacks; the catalog has 540 technique keys, 856 command records, and exactly 146 technique IDs marked `technique_relevant_bounded`; every bounded technique has Windows, Linux, and macOS runner records plus an explicit scenario and expected telemetry |
| J55 | Accessibility | Walk forward and backward through the welcome, actor, scope, review, and export screens with the keyboard | Focus moves to each new screen heading and every step has no serious accessibility violations | The active element is the destination `h1` after forward, back, reached-step, resume/import, and restart transitions; axe-core reports zero `serious` or `critical` violations on every wizard screen |
| J56 | Bound imported plans | Resume documents at and beyond each stage, per-stage technique, aggregate technique, command-length, and ATT&CK-ID boundary | Accepts valid boundary values and rejects values beyond them without changing screens | 1 and 32 non-empty stages, 2,000 techniques in a stage, 4,000 aggregate techniques, and a 10,000-character command are accepted; zero or 33 stages, an empty stage, 2,001 techniques in one stage, 4,001 in aggregate, a 10,001-character command, or a malformed technique ID produces the documented toast and leaves the welcome screen usable |
| J57 | Enforce exact origins | Send a mutating request with a valid CSRF token and vary only `Origin` | Compares scheme, host, and effective port rather than hostname text alone | Foreign host, `null`, wrong scheme, and wrong port return HTTP 403 with `error = forbidden`; a matching `http://[::1]:5000` origin is accepted when the request host is `[::1]:5000` |
| J58 | Propagate Windows install failures | Run `.\install.ps1` with each native child command forced to return non-zero | Stops at the failed step | PowerShell exits non-zero with the matching step-specific error and never prints `AdversaryFlow installed and verified.` |
| J59 | Publish remote authentication | Inspect `docs/openapi.yaml` | Describes the bearer-token condition and unauthorised responses | `components.securitySchemes.BearerToken` is HTTP bearer; the contract says it is required for all `/api/*` requests in remote mode, and every documented API operation includes a `401` response |
| J60 | Export operator kit | Click **Download <platform> execution kit** | Builds and downloads a catalog-rebound ZIP without executing commands | HTTP 200 returns a `.zip` containing an `<actor>-plan.csv` and platform-matching `<actor>-execute.ps1` or `<actor>-execute.sh`; plans with bounded exercises also contain `AdversaryFlow-exercises.py`; the toast reads `Execution kit ready: <filename>` |
| J61 | Recover from kit export failure | Make `POST /api/execution-kit` return an error, then click the execution-kit card | Surfaces the failure and restores the control | A toast shows the API message or the status fallback, no download begins, and the execution-kit button is enabled again |
| J62 | Record a failing lab step | Run a downloaded kit whose step exits non-zero and whose cleanup also fails | Records the failure as evidence instead of aborting the session | The runner exits 0; `execution-summary.json`, `execution-results.csv`, `evidence-events.jsonl`, and `SHA256SUMS` are all written; the summary reports `failed_steps = 1` and `completed_steps = 0`; the CSV row records `exit_code = 3` and `cleanup_status = failed`; the generated runner contains no `set -e` statement |
| J63 | Export engagement reports | Click **Generate report**, inspect the preview, then download **HTML**, **PDF**, and **JSON** | The server validates the schema 2.0 plan, rebinds catalog-owned mappings for the command-free human view, renders PDF from HTML, and preserves JSON as the canonical record | Empty/loading/error/ready states are explicit; files are named `AdversaryFlow_<ID>_<Name>_report.html`, `_report.pdf`, and `.json`; HTML/PDF contain techniques, telemetry, ATT&CK detection guidance, catalog Sigma references only when present, evidence, and gaps, but no runnable commands |

---

*The AdversaryFlow web service generates plans and exports; it does not execute
commands. Portable runners execute only after operator approval and belong only
in a disposable lab you are authorised to test.*
