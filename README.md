# AdversaryFlow

**Development-lab adversary-emulation workflow planner.** Pick a threat-actor
campaign, and AdversaryFlow pulls its TTPs from the **live MITRE ATT&CK STIX
feed**, orders them into an end-to-end kill-chain workflow, and attaches an
ATT&CK-aligned lab command to every technique so detection teams can exercise
and measure coverage.

> AdversaryFlow is designed for disposable development labs rather than
> production deployment. The application never executes commands. It generates
> a portable, operator-controlled execution kit for use on a separate lab host.

---

## What it does

AdversaryFlow is a **fully guided, 4-step wizard** — no dead ends, every screen
tells you what to do next, with a progress stepper you can navigate freely once
steps are reached:

1. **Choose a threat actor** — a searchable, filterable gallery of every
   ATT&CK group and named campaign mapped in the selected domains. Filter by
   name / alias / ATT&CK ID. ICS and Mobile actors appear when those domains
   are turned on.
2. **Scope the engagement** — pick the command platform (Windows / Linux /
   macOS), toggle kill-chain stages on/off, include or drop pre-compromise
   tactics, and see a live plan preview update as you go.
3. **Review & track the plan** — review structured risk, privilege, network,
   expected-telemetry, prerequisites, rollback, and cleanup metadata before
   copying a command. Record command result (ran / failed / skipped) separately
   from detection result (alerted / silent / blocked / not instrumented), plus
   evidence notes, run IDs, timestamps, exit codes, output hashes, receipt
   digests, SIEM/endpoint references, target context, and cleanup verification.
   Progress autosaves in this browser; `j` / `k` move between techniques and
   `c` copies the focused command.
4. **Export** — download a one-click **operator execution kit** containing a CSV
   plan and self-contained PowerShell or Bash runner. Generate command-free
   purple-team reports as **PDF** or **HTML**, preserve the schema-versioned
   **JSON** evidence record, or export **Markdown** and a commented **runbook**.

The execution kit is an offline handoff artifact. Direct catalog commands need
no AdversaryFlow installation, Python, or network access. Bounded synthetic
steps ship a portable exercise script that needs Python 3.10+ beside the kit.
Every step requires explicit approval and offers run, edit, skip, or abort
controls. The runner records
command edits, timestamps, output hashes, exit codes, cleanup, and detection
assessment, then produces HTML/Markdown reports and machine-readable evidence.

Under the hood:

* **Live TTP pull** — the actor's `uses` relationships are resolved from the
  official ATT&CK STIX 2.1 bundle (auto-downloaded & cached, 7-day TTL).
* **Kill-chain order is derived from the live STIX matrix**, not hardcoded, so
  the tool stays correct as ATT&CK evolves its tactics — including the current
  split of *Defense Evasion* into **Stealth** and **Defense Impairment**.
* **Lab exercise per TTP** — a curated library of **540 technique keys and 856 platform records**
  covers **every technique used by any of the 232 actors**, so a real actor
  workflow comes back 100% `curated` with 0 `fallback`. Entries use direct
  technique-specific commands where the behaviour is safe; behaviours that
  require targeting people, destructive actions, or external adversary
  infrastructure use one of 25 bounded exercise families. These 146 exercises
  create technique-relevant synthetic records, child-process activity,
  temporary artifacts, or loopback-only protocol events and emit a
  digest-protected JSON receipt. A receipt is self-reported execution evidence;
  it must be correlated with endpoint or SIEM telemetry for independent proof.
  A harmless marker child process carries the run ID into process telemetry,
  and `adversaryflow-telemetry` applies the explicit per-technique pass gate to
  normalized endpoint/SIEM exports. See
  [Independent telemetry correlation](docs/TELEMETRY.md).
  Every entry has structured safety, prerequisites, expected telemetry, notes,
  and cleanup metadata; a tactic-aware
  fallback covers any technique a future ATT&CK release
  introduces before its curated test is written.

## Architecture

AdversaryFlow is a local Flask service plus a React/TypeScript SPA. Flask owns
the safety boundary, live STIX cache, catalog rebinding, diagnostics, reports,
and offline-kit serialization. The browser owns the guided workflow,
autosaved evidence, heatmap, and pre-copy review experience. There is no web
service execution path.

```text
React + TypeScript SPA
  │ same-origin JSON + CSRF token
  ▼
Flask planner API ──► live ATT&CK STIX cache
  │                 └► bounded catalog + safety metadata
  ├──► command-free HTML/PDF reports
  └──► operator-gated offline ZIP ──► disposable lab host
```

The full component map, data flows, trust boundaries, persistence model, and
build pipeline are documented in [Architecture](docs/ARCHITECTURE.md).

**Data source:** [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data)
(`master` tracks the latest ATT&CK release). Enterprise by default; ICS and
Mobile domains are supported via `?domains=enterprise,ics,mobile`.

## Run it

New operators should follow the copy/paste handbook
[Getting started](docs/GETTING_STARTED.md) (install, first verified PoC,
everyday use, remediation, recovery, upgrades, and support).

The fastest supported path from a source checkout is Docker Compose:

```bash
git clone https://github.com/rikterskale/AdversaryFlow.git
cd AdversaryFlow
docker compose up
```

The startup banner prints <http://127.0.0.1:5000>, a per-start API token,
and the exact next step. Enter that token when the browser asks for it. The
host port is published on loopback only, the service still enforces its
non-loopback bearer-token gate inside the container, and the validated ATT&CK
STIX cache persists in the `adversaryflow-stix-cache` volume. Set
`ADVERSARYFLOW_PORT` to choose another host port; set
`ADVERSARYFLOW_API_TOKEN` before startup only when you need a stable token.

Stop with Ctrl+C. A later `docker compose up` is safe to rerun and reuses the
cache.

For a safe first dry-run, open the printed URL, enter the printed token, and:

1. Choose any ATT&CK actor or campaign.
2. Keep the detected platform and default guardrails, then select **Build plan**.
3. Review the heatmap and first technique card without copying a command.
4. Select **Finish & export**, then download the PDF report or schema-versioned
   JSON record.

That completes the planner journey without executing anything. On a typical
connected workstation it takes less than five minutes; the initial ATT&CK
download is the only network-dependent step. See the exact copy/paste path in
[Getting started](docs/GETTING_STARTED.md).

Native launchers remain supported alternatives:

Linux and macOS:

```bash
./run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

The native launcher opens <http://127.0.0.1:5000> when ready. The first enterprise
launch downloads and validates approximately 54 MB of STIX data in the
background while the UI reports progress. Later starts do not reinstall
dependencies. Use **↻ Refresh feed** (or
`POST /api/refresh`) to pull the newest ATT&CK release.

To install an isolated copy from a [GitHub Release](https://github.com/rikterskale/AdversaryFlow/releases)
wheel (or a wheel you built):

```bash
pipx install ./adversaryflow-0.4.0-py3-none-any.whl
adversaryflow --open
```

Install that wheel file. Do not run `pipx install adversaryflow`.

Manual setup, if you prefer:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --require-hashes --requirement requirements.lock
python -m pip install --require-hashes --requirement requirements-build.lock
python -m pip install --no-build-isolation --no-deps --editable .
adversaryflow
```

The launcher accepts `--host`, `--port`, `--cache-dir`, `--offline`,
`--no-preload`, `--open`, `--allow-remote`, `--api-token`, and `--version`.
Non-loopback binds require both `--allow-remote` and a bearer token; see
[Operations](docs/OPERATIONS.md). Maintenance
commands include `doctor`, `cache-status`, `cache-refresh`, and `cache-clear`.
See [Getting started](docs/GETTING_STARTED.md),
[installation](docs/INSTALL.md), and
[operations](docs/OPERATIONS.md) for supported platforms, cache locations,
offline use, upgrades, and health behavior. Use the dedicated
[troubleshooting matrix](docs/TROUBLESHOOTING.md) for symptom-to-fix guidance.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/actors` | List groups & campaigns that have techniques mapped |
| `GET /api/workflow/<stix_id>` | Full kill-chain workflow + lab commands |
| `POST /api/refresh` | Force re-download of the live STIX feed |
| `GET /api/health` | Liveness, readiness, version, loaded domains, and data versions |
| `GET /api/doctor` | Structured host self-test used by the GUI health panel |
| `POST /api/execution-kit` | Catalog-rebound, operator-gated offline kit |
| `POST /api/report/{format}` | Command-free HTML or PDF purple-team engagement report |

Mutating endpoints require a same-origin request token, refreshes are
serialized/rate-limited, and non-loopback binding requires explicit opt-in.
The complete HTTP contract is checked in as [OpenAPI 3.1](docs/openapi.yaml).
Schema 2.0 JSON exports conform to the
[AdversaryFlow plan schema](schemas/adversaryflow-plan.schema.json); they are
AdversaryFlow-native and do not claim direct VECTR or Caldera compatibility.

### The `domains` parameter (ATT&CK domain toggle)

MITRE splits ATT&CK into three **domains**, each its own STIX bundle:

| Domain | What it covers | Example techniques |
| --- | --- | --- |
| `enterprise` (default) | Windows/Linux/macOS/cloud/containers/network | most named APT activity |
| `ics` | Industrial Control Systems / OT | `T0836 Modify Parameter`, `T0831 Manipulation of Control` |
| `mobile` | Android / iOS | `T1655 Masquerading`, mobile C2 |

Passing `?domains=enterprise,ics,mobile` makes the backend download and index
those bundles too, so the actor list and each workflow include ICS/Mobile
groups and techniques (e.g. ICS-focused actors like Sandworm's OT activity).
With only `enterprise` (the default) those actors/techniques are simply not in
scope. The actor screen exposes the same domain choices and supports combined
views. Each normalized domain set has an independent in-memory index and data
version.

## Extending the command library

The lab command catalog lives in two places. Each entry declares a platform,
command, operational note, and optional cleanup command:

* `backend/command_catalog.py` — the hand-tuned **core** (`CURATED`) and the
  tactic fallback. Core entries win on any ID collision.
* `backend/ext_part1..14.py` — the **per-technique exercise expansion**, sliced
  into reviewable files and auto-merged by `command_catalog_extended.py`.

To add or refine a test, add the ATT&CK ID to `CURATED` (core) or the relevant
`PART` dict with one or more `c(platform, command, note, cleanup)` entries.
`ext_part*.py` files are pure data, so they can be reviewed technique-by-technique.
Run the coverage check to confirm no actor technique falls back to a generic test:

```bash
python -c "from backend import attack_data as a, command_catalog as c; idx=a.get_index(['enterprise']); u={t['attack_id']:t for x in idx.list_actors() for t in idx.actor_techniques(x['stix_id'])}; print('fallback:', [k for k,t in u.items() if c.get_commands(t['attack_id'],t['name'],t['tactics'])['source']=='fallback'])"
```

## Where this sits

AdversaryFlow is a lightweight planner in the same space as **MITRE Caldera**,
**Atomic Red Team**, and **VECTR** — focused specifically on turning a *named
threat actor* into an *ordered, runnable lab workflow*. Its web service never
executes commands; it produces plans and portable, operator-gated runners for
use in a disposable test environment.

## Development and releases

Run the local verification suite with:

```bash
.venv/bin/python -m unittest discover --verbose
bash -n install.sh run.sh
npm run check:frontend
npm run test:e2e
```

Lint and type checks (configured in `pyproject.toml`, tooling pinned in
`requirements-dev.lock`):

```bash
.venv/bin/python -m pip install --require-hashes --requirement requirements-dev.lock
.venv/bin/ruff check .
.venv/bin/mypy
```

CI tests Python 3.10–3.14 across Linux, Windows, and macOS, runs Playwright
browser tests, enforces `ruff` and `mypy`, smoke-tests the built wheel on all
three platforms, scans with CodeQL, and produces checksums and a CycloneDX SBOM. See [CONTRIBUTING.md](CONTRIBUTING.md),
[SUPPORT.md](SUPPORT.md), [GOVERNANCE.md](GOVERNANCE.md), and
[the release guide](docs/RELEASING.md).

AdversaryFlow is licensed under [Apache-2.0](LICENSE). Use it only in an
authorized disposable lab; see [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). Report
vulnerabilities privately according to [SECURITY.md](SECURITY.md).
