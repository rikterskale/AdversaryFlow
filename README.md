# AdversaryFlow

**Development-lab adversary-emulation workflow planner.** Pick a threat-actor
campaign, and AdversaryFlow pulls its TTPs from the **live MITRE ATT&CK STIX
feed**, orders them into an end-to-end kill-chain workflow, and attaches an
ATT&CK-aligned lab command to every technique so detection teams can exercise
and measure coverage.

> AdversaryFlow is designed for disposable development labs rather than
> production deployment. It generates command plans and exports; it does not
> execute commands.

---

## What it does

AdversaryFlow is a **fully guided, 4-step wizard** — no dead ends, every screen
tells you what to do next, with a progress stepper you can navigate freely once
steps are reached:

1. **Choose a threat actor** — a searchable, filterable gallery of 220+ ATT&CK
   groups (`APT29`, `FIN7`, `Lazarus`, …) and named campaigns, with popular
   actors surfaced as quick-pick chips. Filter by name / alias / ATT&CK ID.
2. **Scope the engagement** — pick the command platform (Windows / Linux /
   macOS), toggle kill-chain stages on/off, include or drop pre-compromise
   tactics, and see a live plan preview update as you go.
3. **Run & track the plan** — the kill chain is laid out stage-by-stage with a
   left rail, a completion **progress ring**, and a lab command per technique
   you can copy and **check off as you run it** (progress persists in
   `localStorage` per actor).
4. **Export** — download the scoped plan as **Markdown**, schema-versioned
   **JSON**, or a platform-specific commented **runbook**.

Under the hood:

* **Live TTP pull** — the actor's `uses` relationships are resolved from the
  official ATT&CK STIX 2.1 bundle (auto-downloaded & cached, 7-day TTL).
* **Kill-chain order is derived from the live STIX matrix**, not hardcoded, so
  the tool stays correct as ATT&CK evolves its tactics — including the current
  split of *Defense Evasion* into **Stealth** and **Defense Impairment**.
* **Lab command per TTP** — a curated library of **530+ precise tests**
  covers **every technique used by any of the 227 actors**, so a real actor
  workflow comes back 100% `curated` with 0 `fallback`. Each test is a
  technique-specific command with notes and cleanup metadata; a tactic-aware
  fallback covers any technique a future ATT&CK release
  introduces before its curated test is written.

## Architecture

```
AdversaryFlow/
├── backend/
│   ├── app.py                       # Flask API + serves the frontend
│   ├── attack_data.py               # live STIX download/cache + kill-chain indexing
│   ├── command_catalog.py           # curated core library + tactic fallback
│   ├── command_catalog_extended.py  # auto-merges the ext_part* files below
│   ├── ext_helper.py                # shared helper for the part files
│   ├── ext_part1..14.py             # precise lab tests, one reviewable slice each
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js              # actor picker, workflow render, exporters
├── data/                   # legacy checkout cache location (git-ignored)
├── docs/                   # install, operations, API, export, release guides
├── schemas/                # versioned JSON export schema
├── tests/                  # unit and contract tests
├── pyproject.toml          # package metadata + adversaryflow command
├── requirements.lock       # pinned runtime set
├── run.sh / run.ps1        # one-command launchers
└── README.md
```

**Data source:** [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data)
(`master` tracks the latest ATT&CK release). Enterprise by default; ICS and
Mobile domains are supported via `?domains=enterprise,ics,mobile`.

## Run it

Linux and macOS:

```bash
./run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

Then open <http://127.0.0.1:5000>. The first enterprise launch currently
downloads approximately 54 MB of STIX data into the per-user cache. Later
starts do not reinstall dependencies. Use **↻ Refresh feed** (or
`POST /api/refresh`) to pull the newest ATT&CK release.

Manual setup, if you prefer:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install .
adversaryflow
```

The launcher accepts `--host`, `--port`, `--cache-dir`, `--offline`,
`--no-preload`, and `--version`. See [installation](docs/INSTALL.md) and
[operations](docs/OPERATIONS.md) for supported platforms, cache locations,
offline use, upgrades, health behavior, and troubleshooting.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/actors` | List groups & campaigns that have techniques mapped |
| `GET /api/workflow/<stix_id>` | Full kill-chain workflow + lab commands |
| `POST /api/refresh` | Force re-download of the live STIX feed |
| `GET /api/health` | Liveness, readiness, version, loaded domains, and data versions |

The complete HTTP contract is checked in as [OpenAPI 3.1](docs/openapi.yaml).
JSON exports conform to the
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
* `backend/ext_part1..14.py` — the **precise per-technique expansion**, sliced
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
threat actor* into an *ordered, runnable lab workflow*. It does not execute
commands; it produces plans and exports for use in a disposable test environment.

## Development and releases

Run the local verification suite with:

```bash
.venv/bin/python -m unittest discover --verbose
node --check frontend/app.js
bash -n install.sh run.sh
```

CI tests Python 3.10, 3.12, and 3.14, builds the wheel and source distribution,
and verifies the command-line entry point. See [CONTRIBUTING.md](CONTRIBUTING.md),
[SUPPORT.md](SUPPORT.md), [GOVERNANCE.md](GOVERNANCE.md), and
[the release guide](docs/RELEASING.md).
