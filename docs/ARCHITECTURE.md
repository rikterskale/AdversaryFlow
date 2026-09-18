# Architecture

AdversaryFlow is an authorized adversary-emulation **planner**. Its web
service assembles ATT&CK-mapped workflows and serializes artifacts; it has no
code path that executes a catalog command, connects to an emulation target, or
operates a C2 channel. Execution is a separate, explicit operator action on a
disposable lab host.

## System context

```text
Official MITRE ATT&CK STIX 2.1 feed
                 │ HTTPS download + validation
                 ▼
┌──────────────────────────────────────────────────────────────┐
│ Local AdversaryFlow service                                  │
│                                                              │
│  attack_data.py ──► AttackIndex ──► command_catalog.py       │
│       │                                  │                   │
│       └── validated STIX cache             └── safety metadata│
│                         │                                    │
│                         ▼                                    │
│  app.py / Flask API ◄──── React + TypeScript SPA             │
│       │                  (same origin, browser autosave)      │
│       ├── diagnostics.py ──► PASS/FAIL self-test              │
│       ├── reporting.py ───► command-free HTML → PDF           │
│       │                    └► canonical plan JSON              │
│       └── execution_kit.py ► catalog-rebound offline ZIP     │
└──────────────────────────────────────────────────────────────┘
                                      │ deliberate file transfer
                                      ▼
                         Authorized disposable lab host
                         (operator approves every step)
```

## Runtime components

| Component | Responsibility | Security boundary |
| --- | --- | --- |
| `backend/app.py` | Flask routes, static frontend, startup lifecycle, request IDs, response hardening, CSRF and bearer enforcement | Never launches catalog commands |
| `backend/attack_data.py` | Downloads, validates, hashes, caches, and indexes the official STIX bundles; derives live tactic order | Only the configured MITRE source is accepted |
| `backend/command_catalog.py` and `ext_part*.py` | Curated technique/platform records and bounded fallback selection | Public ATT&CK IDs and reviewed, bounded exercises only |
| `backend/command_safety.py` | Normalizes risk, privilege, network, prerequisite, telemetry, and rollback metadata | Safety metadata travels with every command record |
| `backend/lab_exercises.py` | Portable bounded synthetic exercise families and digest-protected receipts | Runs only when an operator invokes the exported script on a lab host |
| `backend/execution_kit.py` | Rebinds a submitted plan to the server catalog and emits the offline CSV/runner ZIP | Browser-supplied command bodies are discarded |
| `backend/reporting.py` | Builds a deterministic command-free report view, self-contained HTML, HTML-derived PDF, and canonical plan JSON | Escapes plan text, omits executable content from human reports, and never executes plan content |
| `backend/diagnostics.py` | Shared CLI/API checks for runtime, Docker, assets, port, cache, disk, and ATT&CK reachability | Read-only except for a temporary cache-writability probe |
| `backend/telemetry.py` | Normalizes independently collected endpoint/SIEM exports and applies bounded-exercise acceptance criteria | Does not collect from remote targets or execute exercises |

## Frontend

The frontend is a Vite-built React 18 and TypeScript SPA. Tailwind/PostCSS and
the CSS design-token layer produce the stable `frontend/styles.css`; Vite
produces `frontend/app.js` and `frontend/index.html`, which Flask and the wheel
serve without a Node runtime.

```text
frontend/
├── src/
│   ├── api/                 # typed contracts, guards, authenticated fetches
│   ├── app/                 # lifecycle, shell, theme, help and health panels
│   ├── components/          # buttons, dialogs, icons and feedback states
│   ├── features/
│   │   ├── actors/          # actor/campaign gallery and domain filters
│   │   ├── scope/           # platform, tactic and safety scope + preview
│   │   ├── review/          # heatmap, cards, evidence and keyboard workflow
│   │   ├── export/          # schema export, reports and offline-kit handoff
│   │   └── welcome/         # entry, resume and import experience
│   ├── state/               # Zustand state and resilient local autosave
│   └── styles/              # design tokens and responsive component styles
├── vite.config.ts           # stable production asset names + dev API proxy
├── tailwind.config.js
└── index.html, app.js, styles.css  # checked-in production build
```

TanStack Query owns server state and retry/loading behavior. Zustand owns the
wizard, selected domains and actor, scope, evidence, and schema-imported
workflow. Only the resumable planner state is written to browser local
storage. Storage failure is surfaced in the UI so the operator can export JSON
instead of silently losing work.

## Core request and data flows

### Startup and ATT&CK preparation

1. The browser requests `GET /api/session`. In remote mode it first supplies
   the configured bearer token.
2. The SPA polls `GET /api/bootstrap`; it may initiate the CSRF-protected
   bootstrap when data has not been loaded.
3. `attack_data.py` reuses a validated fresh cache or downloads the selected
   official STIX bundle. Download size, bundle shape, domain, metadata, and
   recorded digest are validated before the cache replaces a prior copy.
4. `AttackIndex` resolves actors, `uses` relationships, techniques, matrices,
   tactics, data sources, and detection guidance.
5. Readiness becomes green only when both the service lifecycle and the
   requested ATT&CK index are ready.

### Guided planning

1. `GET /api/actors` returns groups and campaigns for the selected ATT&CK
   domains.
2. `GET /api/workflow/<stix-id>` resolves and orders the actor's techniques
   from the live matrix.
3. Each technique is joined to an exact-platform curated command or the
   bounded fallback. The SPA applies the operator's network, administrator,
   and high-risk scope without substituting commands from another platform.
4. The review workspace displays tactic coverage, command fidelity, expected
   telemetry, detection guidance, risk, privileges, network effects,
   prerequisites, cleanup, and rollback before copy is possible.
5. Command outcome and detection result are independent evidence fields and
   autosave locally.

### Export and handoff

The browser builds the strict schema 2.0 plan record. On the Export step,
**Generate report** requests HTML, presents explicit empty/loading/error/ready
states, and places the self-contained document in a sandboxed preview.

`POST /api/report/html` and `POST /api/report/pdf` discard submitted command
bodies through catalog rebinding, then render technique coverage, expected
telemetry and acceptance criteria, ATT&CK data sources/detection guidance,
catalog Sigma references only when explicitly present, complete evidence, and
categorized gaps. PDF consumes the same generated HTML. Reports contain no
runnable command text and make no report-time network calls.

`POST /api/report/json` returns the submitted schema 2.0 plan unchanged as the
canonical machine-readable evidence and resume record. It is not a parallel
report model. The HTML/PDF source-plan digest is calculated from this input.

`POST /api/execution-kit` performs the same catalog rebinding and emits an
integrity-bound ZIP. The kit is moved offline to the disposable host. Its
PowerShell or Bash runner shows the exact step and safety metadata, then asks
the operator to run, edit, skip, or abort. It never calls the web service.

## Trust boundaries and controls

- **Authorization:** [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md), product copy,
  and the container banner constrain use to authorized disposable labs.
- **Network bind:** native service default is `127.0.0.1`. Any non-loopback
  bind requires both explicit `--allow-remote` and a bearer token. Compose
  publishes only a loopback host port and still uses the internal remote-mode
  bearer gate.
- **Browser mutations:** refresh, bootstrap, kit, and report requests require
  the session's same-origin token and exact-origin validation.
- **Untrusted imports:** schema imports are structurally validated. Imported
  command text is classified as high risk in the browser and is never trusted
  by server-side kit/report generation.
- **Catalog rebound:** server-generated artifacts resolve every technique
  against the current bounded catalog. An uploaded plan cannot smuggle an
  arbitrary payload into a branded kit or report.
- **Response hardening:** CSP, frame denial, MIME sniffing prevention,
  same-origin resource/opener policy, no-referrer, and no-store API responses
  are applied centrally.
- **Resource limits:** ordinary JSON requests use the small global body cap;
  complete plan artifact endpoints have a 5 MiB cap and a 4,000-step limit.
- **Secrets:** no secret is checked in. Compose generates a per-start token
  unless an operator supplies `ADVERSARYFLOW_API_TOKEN` at runtime.

## Persistence

| Data | Location | Lifecycle |
| --- | --- | --- |
| STIX bundles and provenance | Per-user cache or `adversaryflow-stix-cache` volume | Seven-day freshness; explicit refresh/clear commands |
| In-memory ATT&CK indexes | Flask process | Rebuilt per normalized domain set and invalidated on refresh |
| Wizard scope and evidence | Browser local storage | Versioned key; export JSON before clearing browser data |
| API/CSRF tokens | Process memory; Compose token also in a mode-0700 tmpfs file | Regenerated with the service/container unless explicitly supplied |
| Reports, JSON and kits | Browser download destination | Owned and retained by the operator |

The service has no database and does not upload plans, evidence, or reports.

## Repository and deployment layout

```text
AdversaryFlow/
├── backend/                 # Flask planner, STIX, catalog, kits and reports
├── frontend/
│   ├── src/                 # React + TypeScript source
│   └── index.html, app.js, styles.css  # checked-in production bundle
├── schemas/                 # schema-versioned plan and evidence contracts
├── docs/                    # operator, architecture, API and release guides
├── tests/                   # Python contracts plus Playwright journeys
├── docker/
│   ├── entrypoint.sh        # token generation + printed startup handoff
│   └── healthcheck.py       # authenticated container readiness probe
├── Dockerfile               # pinned Node build + Python wheel/runtime stages
├── docker-compose.yml       # loopback port, cache volume and hardening
├── run.sh / run.ps1         # supported native launchers
└── pyproject.toml + requirements*.lock
```

The same application artifact is used across all supported launch paths:

| Profile | Process boundary | Persistent state | Authentication |
| --- | --- | --- | --- |
| Docker Compose | Non-root, read-only container with dropped capabilities | Named STIX cache volume | Generated or supplied bearer token plus same-origin mutation token |
| Native launcher | Waitress on loopback by default | Per-user STIX cache | Same-origin mutation token; bearer required only after explicit remote opt-in |
| pipx wheel | Isolated packaged CLI and checked-in SPA bundle | Per-user STIX cache | Same as native launcher |

Compose publishes only `127.0.0.1:${ADVERSARYFLOW_PORT:-5000}`. Its internal
`0.0.0.0` bind deliberately exercises the service's remote-mode bearer gate;
it does not make the host listener public.

## Packaging and deployment

Vite compiles stable frontend assets before package builds. `pyproject.toml`
installs those assets with the Flask package. Native launchers create an
isolated virtual environment from hash-locked requirements; pipx installs the
same wheel contract.

The multi-stage Docker build uses a digest-pinned Python base. The runtime is
non-root, read-only, capability-free, and uses tmpfs only for temporary files
and the generated token. Docker Compose adds the persistent STIX volume,
loopback-only publication, and an authenticated readiness healthcheck.

## Verification pipeline

- Python unit, contract, UAT, schema, safety, kit, reporting, and diagnostics
  tests run on Python 3.10 and 3.14 across Linux, Windows, and macOS, with an
  additional Python 3.12 Linux job.
- TypeScript type checking, Vite production builds, Vitest component/model
  tests, and Playwright browser journeys cover the frontend.
- Compose smoke builds the real image and waits for authenticated
  `/api/health` readiness.
- Ruff, mypy, CodeQL, release validation, wheel smoke tests, CycloneDX SBOM,
  and release checksums guard the shipped artifacts.

See [OpenAPI 3.1](openapi.yaml), [export formats](EXPORTS.md),
[operations](OPERATIONS.md), and [telemetry](TELEMETRY.md) for the detailed
contracts at each boundary.
