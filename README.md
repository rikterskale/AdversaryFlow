# AdversaryFlow v0.3.0

![CI](https://github.com/rikterskale/adversaryflow/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-informational)
![License](https://img.shields.io/badge/license-Apache--2.0-green)

AdversaryFlow is a threat-informed red team scenario generator for authorized, collaborative purple-team exercises. It resolves a threat actor, builds a claim-level cited TTP dossier, adapts observed behaviors to the target environment and Rules of Engagement (RoE), and produces safe exercise equivalents rather than literal destructive or criminal actions.

Version 0.3.0 runs the same way on Windows, Linux, and macOS, with a stdlib-only
task runner, one-command bootstrap scripts, and a cross-platform CI matrix.

New users should follow the detailed [`INSTALLATION.md`](INSTALLATION.md) and
[`USAGE.md`](USAGE.md) guides. They cover Windows, Linux, macOS, Docker, offline
deployment, live provider setup, request design, storage, caching, automation,
upgrades, and troubleshooting. [`INSTALLATION_REVIEW.md`](INSTALLATION_REVIEW.md)
records the tested paths, findings, fixes, and remaining coverage. The sections
below remain a compact reference.

## Try it in three commands

The demo is deterministic, makes no network requests, and needs no API keys:

```bash
python tasks.py setup
python -m adversaryflow.cli validate-request --request examples/apt29_request.json
python tasks.py demo
```

Use `python3` on Linux/macOS or `py` on Windows if `python` is not the name of
your interpreter. The generated report is `reports/apt29_scenario.md`; its audit
trace is beside it at `reports/apt29_scenario.trace.json`.

## What changed in v0.2

The production-grounding slice is now implemented:

- real Brave Web Search adapter with query-time domain restrictions and mandatory post-result allowlist filtering;
- source fetching with HTTPS enforcement, redirect-by-redirect allowlist checks, DNS/IP checks with connection pinning, response-size limits, content hashes, publication-date extraction, and extraction status;
- HTML, text, JSON, XML, and PDF source extraction;
- claim-level source excerpts and a claim-to-source citation graph;
- a strict Pydantic response schema for every one of the 12 model nodes;
- bounded provider retries and schema-repair calls with complete attempt traces;
- deterministic claim-evidence support validation with citation coverage and unsupported-claim blocking;
- richer Markdown reporting for dossier evidence, claim edges, factuality findings, retries, and source manifests.

## Design principles

- **Grounded before generated:** scenario construction depends on a documented TTP dossier.
- **Hybrid retrieval:** stable ATT&CK data can be pinned locally; fast-moving detections, advisories, and tool documentation are retrieved live.
- **Prompt guidance plus hard controls:** cached philosophy and operational constraints are backed by typed schemas, deterministic RoE checks, rule-based safety checks, source provenance, URL validation, claim-evidence support validation, and human approval gates.
- **Safe equivalence:** when an observed adversary behavior cannot be performed safely, the system produces a proof-of-capability simulation on a designated test asset.
- **No silent invention:** unsupported final actor claims fail the claim-evidence gate by default. This lexical evidence-link check is not semantic entailment verification.
- **No dead citations:** cited sources must be allowlisted, fetched, hashed, extracted, and connected to the exact claim they support.

## Twelve-call orchestration DAG

```text
Call 1: actor identity + query planner
                |
   allowlisted live search + local ATT&CK
                |
   validation, extraction, chunking, hashing
                |
      +---------+----------+
      |         |          |
Call 2       Call 3      Call 4
ATT&CK       advisory    detection/tool
extractor    extractor   extractor
      +---------+----------+
                |
    claim-to-source citation graph
                |
Call 5: cited TTP dossier synthesis
                |
      +---------+----------+
      |         |          |
Call 6       Call 7      Call 8
environment  RoE/safety  telemetry
fit          translator  mapper
      |         |          |
      +----+----+----------+
           |               |
        Call 9          Call 10
        path A          path B
           +------+------+
                  |
Call 11: path adjudication + exercise sequence
                  |
Call 12: final structured composition
                  |
 deterministic safety + factuality gates -> rendering
```

Calls 2–4, 6–8, and 9–10 run concurrently. A successful TTP-based run remains exactly 12 model calls. Additional calls occur only when a provider error or schema-validation failure triggers the bounded repair loop.

## Ad hoc scenarios

AdversaryFlow can also generate authorized red team scenarios that are not tied to a threat actor or ATT&CK TTP dossier. Set `scenario_kind` to `ad_hoc` and provide `ad_hoc_scenario`; the orchestrator skips actor identity resolution, live source retrieval, ATT&CK extraction, and dossier synthesis while keeping RoE translation, telemetry mapping, candidate-path adjudication, safety checks, factuality checks for any emitted claims, trace output, and Markdown rendering.

```bash
adversaryflow generate --request examples/ad_hoc_request.json --output reports/ad_hoc_scenario.md --demo
```

Ad hoc reports intentionally show no grounded TTP dossier unless you explicitly include supported technique mappings in the request. (The commands in this README are written on a single line so they can be pasted directly into PowerShell, `cmd`, or a Unix shell.)

## Requirements & install

- **Python 3.11 or newer.** Check with `python --version` (or `py --version` on Windows).
- **Git**, to clone the repository.

No other prerequisites. The developer workflow is driven by `tasks.py`, a stdlib-only script that behaves identically on Windows, Linux, and macOS.

**Windows:** install Python from [python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"** during setup. That also installs the **`py` launcher**, which is the most reliable way to run Python on Windows — if plain `python` does not work in your terminal, use `py` instead everywhere in this README (e.g. `py tasks.py setup`, `py --version`).

**Linux / macOS:** most systems already ship Python 3.11+; if `python` is not found, use `python3` (e.g. `python3 tasks.py setup`). Install via your package manager (`sudo apt install python3 python3-venv`, `brew install python`, etc.) if needed.

## Quick start: deterministic demo

The fastest path on any operating system is a single command.

**Windows (PowerShell):**

```powershell
python tasks.py setup   # create .venv, install dev tools, seed .env
python tasks.py demo
```

**Linux / macOS:**

```bash
python3 tasks.py setup   # create .venv, install dev tools, seed .env
python3 tasks.py demo
```

`tasks.py` creates the virtual environment, installs the project with its dev
extras, copies `.env.example` to `.env` if you do not have one yet, and then runs
the demo. You do not need to activate the environment manually — every task runs
inside `.venv` automatically.

Before editing an example request, validate it without spending model calls:

```bash
.venv/bin/adversaryflow validate-request --request examples/apt29_request.json
```

On Windows, use `.venv\Scripts\adversaryflow` for commands that directly invoke
the installed CLI.

Prefer the classic manual steps? They work too:

<details>
<summary>Windows (PowerShell)</summary>

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e '.[dev]'
Copy-Item .env.example .env   # optional: edit only for live providers/search

adversaryflow generate --request examples/apt29_request.json --output reports/apt29_scenario.md --demo
```
</details>

<details>
<summary>Linux / macOS</summary>

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env   # optional: edit only for live providers/search

adversaryflow generate --request examples/apt29_request.json --output reports/apt29_scenario.md --demo
```
</details>

Demo mode validates the 12-node DAG, strict schemas, trace generation, safety policy, claim-evidence evaluator, and renderer without external services. It intentionally emits no live actor claims, so its factuality status is reported as N/A rather than 100% verified.

## Developer commands

The same commands run on every platform. Replace `python` with `python3` on Linux/macOS if that is how your interpreter is named.

| Command | What it does |
|---|---|
| `python tasks.py setup` | Create `.venv`, install the project with dev tools, seed `.env`. |
| `python tasks.py test` | Run the test suite (`pytest -q`). |
| `python tasks.py lint` | Ruff lint and format check. |
| `python tasks.py format` | Apply Ruff formatting. |
| `python tasks.py check` | Lint + test (the same gates CI runs). |
| `python tasks.py demo` | Generate the deterministic demo report. |
| `python tasks.py build` | Build the wheel and sdist, then audit the sdist against its allowlist. |
| `python tasks.py clean` | Remove development caches/build output and untracked reports; preserve `.adversaryflow`. |

Unix users who prefer `make` can use the identical targets (`make setup`, `make test`, `make demo`, …); the Makefile simply forwards to `tasks.py`. There are also one-command bootstrap helpers in `scripts/` (`scripts/setup.ps1` / `scripts/setup.sh` and `scripts/demo.ps1` / `scripts/demo.sh`).

## Production configuration

### 1. Model provider

The included model adapter works with OpenAI-compatible chat-completion APIs that support JSON-object output. The simplest cross-platform way to configure it is to copy `.env.example` to `.env` and fill in the values (`python tasks.py setup` does the copy for you). To set the variables directly in a shell instead:

AdversaryFlow automatically loads `.env` from the current project directory.
Values already exported in the process environment take precedence. After editing
the file, run `adversaryflow doctor` to catch missing credentials before generation.

**Linux / macOS:**

```bash
export ADVERSARYFLOW_LLM_BASE_URL="https://your-provider.example/v1"
export ADVERSARYFLOW_LLM_API_KEY="..."
export ADVERSARYFLOW_LLM_MODEL="your-model"
```

**Windows (PowerShell):**

```powershell
$env:ADVERSARYFLOW_LLM_BASE_URL="https://your-provider.example/v1"
$env:ADVERSARYFLOW_LLM_API_KEY="..."
$env:ADVERSARYFLOW_LLM_MODEL="your-model"
```

Every node receives its exact JSON Schema in the system prompt. Returned JSON is validated locally with Pydantic. Invalid output is retried with a repair context containing the previous response and validation errors.

### 2. Brave Search

**Linux / macOS:**

```bash
export ADVERSARYFLOW_SEARCH_PROVIDER="brave"
export ADVERSARYFLOW_BRAVE_API_KEY="..."
```

**Windows (PowerShell):**

```powershell
$env:ADVERSARYFLOW_SEARCH_PROVIDER="brave"
$env:ADVERSARYFLOW_BRAVE_API_KEY="..."
```

The adapter calls the Brave Web Search endpoint and adds `site:` restrictions for the configured allowlist. Search syntax is only a retrieval optimization: every result is independently rejected unless its HTTPS URL is allowlisted. Redirect destinations are checked again during fetch.

To intentionally disable live search, set `ADVERSARYFLOW_SEARCH_PROVIDER` to `null` (or pass `--search-provider null` on the command line).

### 3. Run

If you did not install into a virtual environment, prefix the command with `python -m`, i.e. `python -m adversaryflow.cli generate ...`.

```bash
adversaryflow generate --request examples/apt29_request.json --output reports/apt29_scenario.md --attack-bundle data/enterprise-attack.json
```

### CLI options

| Option | Purpose |
|---|---|
| `--request PATH` | Required scenario request JSON file. |
| `--output PATH` | Markdown or HTML report path; the trace is written next to it with `.trace.json`. |
| `--format markdown|html` | Override format inference from the output file extension. |
| `--demo` | Use the deterministic demo provider and disable live search. |
| `--search-provider brave|null` | Override `ADVERSARYFLOW_SEARCH_PROVIDER` for the run. |
| `--attack-bundle PATH` | Optional pinned Enterprise ATT&CK STIX bundle for local actor/TTP grounding. |
| `--store-dir PATH` | Durable run/cache directory; defaults to `.adversaryflow`. |
| `--no-store` | Skip the immutable run bundle while retaining normal report output. |
| `--no-cache` | Disable both source and model-node cache reads and writes. |
| `--refresh-sources` | Refetch sources and replace fresh URL-index entries. |
| `--refresh-nodes` | Regenerate nodes and replace successful cache entries. |

Other useful commands:

| Command | Purpose |
|---|---|
| `adversaryflow init` | Interactively create a safe starter request. |
| `adversaryflow export-schema` | Export the complete request JSON Schema for editors and integrations. |
| `adversaryflow doctor [--demo] [--check-network]` | Check configuration and optionally verify service credentials. |
| `adversaryflow validate-request --request PATH` | Validate JSON and request rules without external calls. |
| `adversaryflow --version` | Print the installed version. |
| `adversaryflow cache inspect` | Show node/source cache counts and size. |
| `adversaryflow storage status` | Show current and supported storage schema versions. |
| `adversaryflow storage list` | List completed immutable run bundles. |
| `adversaryflow storage verify RUN_ID` | Recompute and verify every artifact hash. |

For local configuration, copy `.env.example` to `.env` and fill in the variables needed by your provider before running the CLI.

## Create your own request

Run `adversaryflow init` for an interactive starter, or supply options for a
repeatable non-interactive workflow:

```bash
adversaryflow init --output my-request.json --actor "Example Actor" --objective "Validate identity incident response" --environment "Purple Team Lab" --mode tabletop
adversaryflow validate-request --request my-request.json
```

The wizard creates conservative RoE defaults that must be reviewed and customized.
The `examples/` directory contains TTP-based, ad hoc, and tabletop templates. Use
`adversaryflow export-schema --output scenario-request.schema.json` to add field
completion and validation to compatible editors.

## Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
| `ADVERSARYFLOW_LLM_BASE_URL` | empty | OpenAI-compatible API base ending before `/chat/completions` |
| `ADVERSARYFLOW_LLM_API_KEY` | empty | Model-provider credential; never persisted |
| `ADVERSARYFLOW_LLM_MODEL` | empty | Provider model identifier |
| `ADVERSARYFLOW_SEARCH_PROVIDER` | `brave` | `brave` or `null` |
| `ADVERSARYFLOW_ALLOWED_DOMAINS` | empty | Comma-separated domains added to the built-in catalog allowlist |
| `ADVERSARYFLOW_BRAVE_API_KEY` | empty | Brave Search credential |
| `ADVERSARYFLOW_REQUEST_TIMEOUT` | `45` | LLM request timeout in seconds |
| `ADVERSARYFLOW_SEARCH_TIMEOUT` | `15` | Search request timeout in seconds |
| `ADVERSARYFLOW_URL_TIMEOUT` | `10` | Per-source fetch timeout in seconds |
| `ADVERSARYFLOW_MAX_SOURCE_BYTES` | `2000000` | Maximum bytes accepted from one source |
| `ADVERSARYFLOW_NODE_MAX_ATTEMPTS` | `3` | Total attempts per model node |
| `ADVERSARYFLOW_RETRY_BASE_DELAY` | `0.25` | Exponential retry base delay |
| `ADVERSARYFLOW_FACTUALITY_THRESHOLD` | `1.0` | Minimum supported-claim ratio |
| `ADVERSARYFLOW_FAIL_ON_FACTUALITY` | `true` | Block output when factuality fails |
| `ADVERSARYFLOW_REQUIRE_GROUNDING` | `true` | Require at least one source-supported ATT&CK technique |
| `ADVERSARYFLOW_STORE_DIR` | `.adversaryflow` | Durable run and cache root |
| `ADVERSARYFLOW_SOURCE_CACHE_TTL` | `86400` | Source URL freshness in seconds |

## Local ATT&CK snapshot

Place a pinned Enterprise ATT&CK STIX 2.1 bundle at:

```text
data/enterprise-attack.json
```

`data/enterprise-attack.json` is intentionally ignored by Git because the bundle can be large; keep `data/.gitkeep` so the directory exists. The loader resolves intrusion sets by name, alias, or external ATT&CK ID and extracts `uses` relationships to techniques, software, and campaigns. Claims supported by the pinned bundle are accepted by the factuality evaluator as local authoritative evidence even when the live ATT&CK page is unavailable.

## Claim-level evidence model

Each factual claim can contain:

```json
{
  "claim_id": "claim-optional-stable-id",
  "text": "The actor used T1059.001 PowerShell.",
  "category": "technique",
  "confidence": "high",
  "technique_ids": ["T1059.001"],
  "source_urls": ["https://attack.mitre.org/groups/G0016/"],
  "supporting_excerpts": [
    {
      "source_url": "https://attack.mitre.org/groups/G0016/",
      "excerpt": "Short passage supporting the claim.",
      "chunk_id": "chunk-..."
    }
  ]
}
```

The graph builder normalizes claim IDs, source IDs, content hashes, excerpts, support methods, and lexical support scores. The final factuality evaluator audits final claims, dossier techniques, and technique IDs used in the selected path.

## Retry and repair behavior

A node is retried when:

- the provider times out or returns an HTTP/API error;
- the provider returns invalid JSON;
- JSON fails the node's strict schema;
- an unexpected field is present;
- a required field has the wrong type.

Each attempt records status, duration, raw output, validation error, parsed output, and attempt count in the trace. Repair calls preserve the original node name and do not bypass safety or factuality policy.

## Output files

Each run produces:

- a Markdown report by default, or a self-contained, printable HTML report when
  the output ends in `.html` or `--format html` is selected;
- a `.trace.json` audit record containing node attempts, retrieval statistics, local ATT&CK context, citation graph, and factuality result.
- unless `--no-store` is selected, an immutable run bundle containing the request,
  complete scenario pack, trace, report, hashes, provider identity, and cache provenance.

```bash
adversaryflow generate --request examples/apt29_request.json --output reports/apt29_scenario.html --demo
```

The renderer intentionally emits operator-level summaries, evidence requirements, telemetry expectations, stop conditions, and cleanup—not exploit code or destructive commands.

See [`STORAGE.md`](STORAGE.md) for the artifact layout, cache-key contract,
freshness policy, migration procedure, maintenance commands, and security guidance.

## Troubleshooting

- **`python` is not found:** try `py` on Windows or `python3` on Linux/macOS.
- **PowerShell blocks a setup script:** run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then rerun `scripts/setup.ps1`.
- **Live generation says configuration is incomplete:** edit `.env` and run `adversaryflow doctor`. For an offline smoke test, use `--demo`.
- **A request is rejected:** run `adversaryflow validate-request --request your-request.json` for field-level errors.
- **Actor grounding fails:** provide Brave Search credentials, a pinned ATT&CK bundle with `--attack-bundle`, or both. Demo and ad hoc modes do not require live actor grounding.

## Remaining production hardening

1. Add provider failover and per-node token/cost budgets.
2. Sign reproducibility bundles and source manifests.
3. Add reviewer identity, approval state, and immutable release records.
4. Add an evaluation corpus for actor precision/recall, citation entailment, safety, realism, and environment fit.
5. Add ATT&CK Navigator export and optional execution-framework export behind separate approval policies.
6. Add a local web interface for request editing, generation progress, and report review.

## Publish to GitHub

The repository includes CI, issue forms, a pull-request template, contribution guidance, an example environment file, and a security policy. See [`GITHUB_SETUP.md`](GITHUB_SETUP.md) for command-line and web-upload instructions.
