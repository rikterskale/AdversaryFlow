# AdversaryFlow

**AI-assisted adversary-emulation workflow planner.** Pick a threat-actor
campaign, and AdversaryFlow pulls its TTPs straight from the **live MITRE
ATT&CK STIX feed**, orders them into an end-to-end kill-chain workflow, and
attaches a **benign, Atomic-Red-Team-style detection-validation command to
every single technique** — so blue/purple teams can exercise their detections
without any destructive action.

> ⚔️ **Authorized purple-team / detection-engineering use only.** Every command
> the tool emits is a *harmless proxy* — discovery calls, LOLBin invocations,
> benign temp-file writes — designed to trip telemetry, not to cause harm.
> Placeholder-only proxies are used for inherently destructive tactics
> (ransomware, shadow-copy deletion, exfiltration). Review every command
> before running it in your environment.

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
   left rail, a completion **progress ring**, and a benign command per technique
   you can copy and **check off as you run it** (progress persists in
   `localStorage` per actor).
4. **Export** — download the scoped plan as **Markdown**, **JSON** (for
   pipelines / VECTR / Caldera), or a commented **runbook**.

Under the hood:

* **Live TTP pull** — the actor's `uses` relationships are resolved from the
  official ATT&CK STIX 2.1 bundle (auto-downloaded & cached, 7-day TTL).
* **Kill-chain order is derived from the live STIX matrix**, not hardcoded, so
  the tool stays correct as ATT&CK evolves its tactics — including the current
  split of *Defense Evasion* into **Stealth** and **Defense Impairment**.
* **Benign command per TTP** — a curated library of **530+ precise tests**
  covers **every technique used by any of the 227 actors**, so a real actor
  workflow comes back 100% `curated` with 0 `fallback`. Each test is a
  technique-specific benign proxy with notes and cleanup steps; a tactic-aware
  fallback remains as a safety net for any technique a future ATT&CK release
  introduces before its curated test is written.

## Architecture

```
AdversaryFlow/
├── backend/
│   ├── app.py                       # Flask API + serves the frontend
│   ├── attack_data.py               # live STIX download/cache + kill-chain indexing
│   ├── benign_commands.py           # curated core library + tactic fallback
│   ├── benign_commands_extended.py  # auto-merges the ext_part* files below
│   ├── ext_helper.py                # shared helper for the part files
│   ├── ext_part1..14.py             # precise benign tests, one reviewable slice each
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js              # actor picker, workflow render, exporters
├── data/                   # cached STIX bundles (git-ignored)
├── run.sh                  # venv + install + launch
└── README.md
```

**Data source:** [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data)
(`master` tracks the latest ATT&CK release). Enterprise by default; ICS and
Mobile domains are supported via `?domains=enterprise,ics,mobile`.

## Run it

```bash
./run.sh
```

Then open <http://127.0.0.1:5000>. The first launch downloads ~35 MB of STIX
data and caches it under `data/`. Use **↻ Refresh feed** (or `POST /api/refresh`)
to pull the newest ATT&CK release.

Manual setup, if you prefer:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && python app.py
```

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/actors` | List groups & campaigns that have techniques mapped |
| `GET /api/workflow/<stix_id>` | Full kill-chain workflow + benign commands |
| `POST /api/refresh` | Force re-download of the live STIX feed |
| `GET /api/health` | Health check |

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
scope. The backend already supports the parameter; wiring a checkbox in the UI
that appends it to the `/api/actors` and `/api/workflow` calls is a small
frontend change.

## Extending the benign library

The benign tests live in two places, both governed by the same safety contract
(no destruction, no reboot-surviving persistence, no privilege changes, no real
network callbacks, `cleanup` for anything that writes):

* `backend/benign_commands.py` — the hand-tuned **core** (`CURATED`) and the
  tactic fallback. Core entries win on any ID collision.
* `backend/ext_part1..14.py` — the **precise per-technique expansion**, sliced
  into reviewable files and auto-merged by `benign_commands_extended.py`.

To add or refine a test, add the ATT&CK ID to `CURATED` (core) or the relevant
`PART` dict with one or more `c(platform, command, note, cleanup)` entries.
`ext_part*.py` files are pure data, so they can be reviewed technique-by-technique.
Run the coverage check to confirm no actor technique falls back to a generic test:

```bash
cd backend && python -c "import attack_data as a, benign_commands as b; idx=a.get_index(['enterprise']); u={t['attack_id']:t for x in idx.list_actors() for t in idx.actor_techniques(x['stix_id'])}; print('fallback:', [k for k,t in u.items() if b.get_commands(t['attack_id'],t['name'],t['tactics'])['source']=='fallback'])"
```

## Where this sits

AdversaryFlow is a lightweight planner in the same space as **MITRE Caldera**,
**Atomic Red Team**, and **VECTR** — focused specifically on turning a *named
threat actor* into a *safe, ordered, runnable detection-validation workflow*.
It does not execute commands for you; it produces the plan and the safe tests
for a human operator to run under authorization.
