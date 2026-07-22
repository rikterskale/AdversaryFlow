# Usage guide

This guide begins with a credential-free exercise, then covers request design,
live providers, reports, durable runs, caching, automation, and troubleshooting.
AdversaryFlow creates planning artifacts; it does not execute adversary actions.

## Command conventions

Examples use `adversaryflow`. If that executable is not on `PATH`, substitute:

```bash
python -m adversaryflow.cli
```

From a repository setup without activation, use `.venv/bin/python -m
adversaryflow.cli` on Linux/macOS or `.venv\Scripts\python.exe -m
adversaryflow.cli` on Windows.

Discover commands at any time:

```bash
adversaryflow --help
adversaryflow generate --help
adversaryflow cache --help
adversaryflow storage --help
```

## Beginner walkthrough: first report without credentials

### 1. Confirm demo readiness

```bash
adversaryflow doctor --demo
```

Demo mode is deterministic, disables live search, uses no API credentials, and
exercises the same schemas, orchestration, safety checks, rendering, storage, and
cache plumbing as a live run.

### 2. Choose an example

| File | Use it for |
|---|---|
| `examples/tabletop_request.json` | Discussion-only identity-compromise exercise; simplest starting point |
| `examples/apt29_request.json` | TTP-based emulation-plan structure using a designated lab asset |
| `examples/ad_hoc_request.json` | A free-form scenario that intentionally skips actor/TTP grounding |

Validate before generation:

```bash
adversaryflow validate-request --request examples/tabletop_request.json
```

Validation makes no model or search calls. Errors identify the JSON field and rule.

### 3. Generate Markdown or HTML

Markdown:

```bash
adversaryflow generate --request examples/tabletop_request.json --output reports/tabletop-md.md --demo
```

Self-contained, printable HTML:

```bash
adversaryflow generate --request examples/tabletop_request.json --output reports/tabletop-html.html --demo
```

The extension selects the renderer. `--format markdown` or `--format html`
overrides inference. An invalid `--format` value is rejected before any provider
call, so a typo costs nothing.

**The two output names differ on purpose.** The trace file is always the output
path with its extension replaced by `.trace.json`, so `reports/x.md` and
`reports/x.html` both write `reports/x.trace.json` and the second run silently
overwrites the first run's trace. Give each run a distinct output stem whenever
you intend to keep its trace. The immutable copy under `.adversaryflow/runs/` is
never overwritten, so a clobbered trace is recoverable from there.

### 4. Review all outputs

For `reports/tabletop-html.html`, inspect:

- `reports/tabletop-html.html`: human-readable exercise plan.
- `reports/tabletop-html.trace.json`: node attempts, cache provenance, retrieval, citations, and factuality data.
- `.adversaryflow/runs/<run-id>/`: immutable request, scenario pack, trace, report, and hash manifest.
- `.adversaryflow/cache/nodes/`: validated reusable demo-node outputs, one file per resolved model node.

Watch the `Model calls:` counter in each run's summary line. The first run of a
given request reports `Model calls: 12`; every later run of the *same* request
reports `0`, because the node cache is keyed on the request, prompts, schemas,
and provider identity — not on the output path or format. So the HTML run above
already reported `0`. To see it again explicitly:

```bash
adversaryflow generate --request examples/tabletop_request.json --output reports/tabletop-third.html --demo
adversaryflow cache inspect
```

`cache inspect` prints one line per cache kind. After a single TTP-based demo
against an otherwise empty store:

```text
nodes: 12 files, 7276 bytes
sources: 0 files, 0 bytes
```

The node count equals the number of resolved model nodes: 12 for a TTP-based
request, 7 for an ad hoc one. Byte totals vary with request content. `sources: 0`
is correct in demo mode, which performs no retrieval.

### 5. Verify the stored run

```bash
adversaryflow storage list
adversaryflow storage verify RUN_ID_FROM_THE_LIST
```

`storage list` prints newest first, one run per line, as
`run-id | created-at | actor | status`. Copy the identifier from the first
column only — everything after the first `|` is metadata.

Verification recomputes each artifact hash and prints `Verified <run-id>`. It
does not rerun the scenario, make model calls, or cost anything. Two failure
modes are distinct and automation should treat them differently: a run ID that
does not exist is a bad argument and exits `2`, while a run whose artifacts no
longer match the manifest prints the mismatching paths in red and exits `1`.

## Create a request

### Interactive wizard

```bash
adversaryflow init --output my-request.json
```

The wizard asks for an actor or label, objective, environment, and—when required—a
designated test asset. It emits conservative RoE defaults, but those defaults are
not an authorization decision. Review every field with the exercise owner.

Two defaults are worth knowing before you run it:

- `init` writes `"mode": "tabletop"`, which is *not* the schema default. A
  hand-written request that omits `mode` gets `emulation_plan`; a wizard-written
  one gets `tabletop`. Pass `--mode emulation_plan` if that is what you want.
- Because the default is `tabletop`, the wizard does not prompt for a designated
  test asset. Ask for one with `--mode`, or add
  `environment.designated_test_assets` by hand before switching modes later.

The wizard also never prompts for `scenario_kind`; it defaults to `ttp_based`
unless you pass `--kind ad_hoc`. Supplying every answer as a flag makes the
command fully non-interactive, which is what you want in scripts — an unanswered
prompt at end-of-input aborts the command and writes nothing.

Create an ad hoc request non-interactively:

```bash
adversaryflow init --output insider-lab.json --kind ad_hoc --actor "Ad Hoc Exercise" --objective "Validate response to unusual synthetic-record access" --environment "Insider Risk Lab" --mode emulation_plan --test-asset LAB-WIN-02 --premise "An approved exercise identity accesses an unusual volume of synthetic customer records from a lab workstation."
```

The command refuses to overwrite an existing file unless `--force` is supplied.

### Request structure

Top-level fields:

| Field | Required/default | Meaning |
|---|---|---|
| `actor` | Required, at least 2 characters | Threat actor name for TTP-based runs or exercise label for ad hoc runs |
| `objective` | Required, at least 5 characters | Defensive capability to validate |
| `scenario_kind` | Default `ttp_based` | `ttp_based` or `ad_hoc` |
| `ad_hoc_scenario` | Required for `ad_hoc` | Free-form premise, at least 10 characters |
| `mode` | Default `emulation_plan` | `tabletop`, `emulation_plan`, or `controlled_validation` |
| `environment` | Required | Platforms, controls, sensitive assets, and designated test assets |
| `roe` | Required | Authorized boundaries, prohibitions, approvals, and timing |
| `post_2020_tradecraft_only` | Default `true` | Enforce the configured minimum source date |
| `minimum_source_date` | Default `2020-01-01` | Earliest accepted observation date |
| `max_attack_path_steps` | Default `8`, range 3–15 | Maximum final path length |
| `output_audience` | Red, blue, exercise control | Intended report audiences |

Non-tabletop modes require at least one `environment.designated_test_assets`
entry. A designated asset should also appear in `roe.authorized_assets`.

Environment fields:

- `name`: recognizable environment or lab name.
- `platforms`: operating systems and major runtime surfaces.
- `identity_systems`: identity providers and directories.
- `cloud_services`: in-scope cloud services.
- `security_tools`: telemetry, EDR, SIEM, DLP, and identity controls.
- `crown_jewels`: synthetic objectives or protected assets being represented.
- `designated_test_assets`: exact assets approved for non-tabletop activity.
- `notes`: connectivity, isolation, and data-handling assumptions.

RoE fields:

- `authorized_assets`, `authorized_users`, and `authorized_phishing_recipients`.
- `prohibited_actions`.
- `no_real_funds_or_transactions` and `no_destructive_execution`.
- `real_brand_impersonation_requires_written_consent`.
- `required_approvals` and `exercise_window`.

Export the authoritative JSON Schema for editor integration:

```bash
adversaryflow export-schema --output scenario-request.schema.json
```

Use `--force` only when intentionally replacing an existing schema file.

## Scenario kinds and modes

### TTP-based

This path resolves an actor, retrieves or loads evidence, creates a cited dossier,
and normally resolves 12 model nodes. Live runs require grounded techniques by
default. A TTP-based run with neither usable live sources nor a suitable local
ATT&CK bundle is expected to fail closed.

### Ad hoc

This path uses the supplied premise, skips actor lookup and TTP dossier retrieval,
and resolves seven model nodes. It is appropriate when the exercise is driven by
a control objective rather than actor attribution.

### Tabletop

Discussion and decision-making only. A designated technical asset is not required.

### Emulation plan

Produces controlled operator-level summaries for later human approval. At least
one designated test asset is required.

### Controlled validation

Produces a narrowly scoped validation plan with the same designated-asset and
safety requirements. AdversaryFlow still does not execute the plan.

## Configure a live model provider

Copy `.env.example` to `.env` in the directory from which the CLI will run.
AdversaryFlow loads that exact current-directory file. Existing process environment
variables take precedence over `.env` values.

Minimum model settings:

```dotenv
ADVERSARYFLOW_LLM_BASE_URL=https://provider.example/v1
ADVERSARYFLOW_LLM_API_KEY=replace-with-secret
ADVERSARYFLOW_LLM_MODEL=model-name
```

The provider must expose an OpenAI-compatible `/chat/completions` endpoint and
support JSON-object response formatting. AdversaryFlow sends each node's JSON
Schema, validates the result locally, and retries bounded provider/schema failures.

Never commit `.env`; it is ignored by Git and excluded from package and Docker
build contexts.

The same care applies to the requests themselves. A scenario request names your
environment, identity systems, security tooling, crown jewels, designated test
assets, authorized users, and rules of engagement. `.gitignore` covers `.env`,
`.adversaryflow/`, and generated `reports/`, but it does not cover a
`my-request.json` you create at the checkout root. Keep working requests outside
the repository, or add your own ignore rule, before running `git add .` or
building a source distribution.

Check presence without making a network call:

```bash
adversaryflow doctor --search-provider null
```

**`doctor` checks for emptiness, not validity.** A variable is reported as
missing only when it is unset or blank, so any placeholder — `changeme`,
`https://your-provider.example/v1`, a stale key — makes the check report
`Ready for live generation`. Treat a passing offline `doctor` as "nothing is
blank," not "the configuration is correct."

Check credentials and service reachability with small authenticated requests:

```bash
adversaryflow doctor --search-provider null --check-network
```

The network check calls the provider's `/models` endpoint. A provider that supports
chat completions but not `/models` may fail this optional diagnostic even though
generation works.

Exit codes: `0` when every selected check passes, `1` when configuration is
incomplete or a connectivity check fails. Incomplete configuration prints one
bullet per missing variable, so you can fix them in a single pass rather than
rerunning after each edit.

## Configure live search

Brave Search is the live search adapter:

```dotenv
ADVERSARYFLOW_SEARCH_PROVIDER=brave
ADVERSARYFLOW_BRAVE_API_KEY=replace-with-secret
```

Then run:

```bash
adversaryflow doctor --check-network
```

To disable search intentionally:

```dotenv
ADVERSARYFLOW_SEARCH_PROVIDER=null
```

or:

```bash
adversaryflow generate ... --search-provider null
```

Disabling search does not disable the default grounding requirement. For a
TTP-based production run, provide a local ATT&CK bundle with usable actor
relationships or enable search. Ad hoc runs do not require actor grounding.

## Local ATT&CK bundle

Place a pinned Enterprise ATT&CK STIX 2.1 bundle at
`data/enterprise-attack.json`, or pass another path:

```bash
adversaryflow generate --request my-request.json --output reports/scenario.md --attack-bundle /approved/catalog/enterprise-attack.json
```

Record the ATT&CK release, download source, retrieval time, and checksum under
your organization's dependency policy. The repository ignores the default bundle
path because the file is large and should be updated deliberately.

## Run live generation

Preflight, validate, then generate:

```bash
adversaryflow doctor --check-network
adversaryflow validate-request --request my-request.json
adversaryflow generate --request my-request.json --output reports/scenario.html --attack-bundle data/enterprise-attack.json
```

Live TTP-based generation can make 12 model calls on a clean cache, plus bounded
repair attempts. Ad hoc generation normally makes seven. Review provider pricing,
rate limits, data handling, and retention before submitting environment details.

## Understand report and trace status

- **Safety gate:** deterministic request and generated-step policy result.
- **Claim-evidence gate:** whether evaluated actor-specific claims have support.
- **Citation coverage:** proportion of audited claims connected to evidence.
- **Source validation:** whether cited sources passed URL/fetch/extraction controls.
- **Model calls:** calls made during this run; cache hits are not counted.
- **Repair calls:** additional attempts after provider or schema failure.

Demo mode intentionally emits no live actor claims, so claim-evidence status is
N/A rather than a misleading 100% pass.

## Durable runs and caching

Default root: `.adversaryflow/`. Override it permanently:

```dotenv
ADVERSARYFLOW_STORE_DIR=/approved/adversaryflow-data
```

or per command:

```bash
adversaryflow generate ... --store-dir /approved/adversaryflow-data
```

Controls:

| Option | Behavior |
|---|---|
| `--no-store` | Keep requested report/trace output but do not create an immutable run bundle |
| `--no-cache` | Make no source or node cache reads/writes |
| `--refresh-sources` | Refetch sources even when the URL index is fresh |
| `--refresh-nodes` | Regenerate nodes even when validated keys match |

Maintenance:

```bash
adversaryflow cache inspect
adversaryflow cache clear --kind nodes
adversaryflow cache clear --kind sources
adversaryflow cache clear --kind all --yes
adversaryflow storage status
adversaryflow storage migrate
adversaryflow storage list
adversaryflow storage verify RUN_ID
```

Cache clearing preserves completed runs. `python tasks.py clean` removes development
caches and generated untracked reports but deliberately preserves `.adversaryflow`.
See `STORAGE.md` before operating a shared or production store.

## Configuration reference

| Variable | Default | Notes |
|---|---:|---|
| `ADVERSARYFLOW_LLM_BASE_URL` | Empty | Required outside demo mode |
| `ADVERSARYFLOW_LLM_API_KEY` | Empty | Required outside demo mode; never persisted |
| `ADVERSARYFLOW_LLM_MODEL` | Empty | Required outside demo mode and included in node-cache identity |
| `ADVERSARYFLOW_SEARCH_PROVIDER` | `brave` | `brave` or `null` |
| `ADVERSARYFLOW_BRAVE_API_KEY` | Empty | Required when search provider is `brave` |
| `ADVERSARYFLOW_ALLOWED_DOMAINS` | Empty | Comma-separated additions to the built-in allowlist |
| `ADVERSARYFLOW_REQUEST_TIMEOUT` | `45` | LLM HTTP timeout seconds |
| `ADVERSARYFLOW_SEARCH_TIMEOUT` | `15` | Search timeout seconds |
| `ADVERSARYFLOW_URL_TIMEOUT` | `10` | Individual source fetch timeout seconds |
| `ADVERSARYFLOW_MAX_SOURCE_BYTES` | `2000000` | Maximum accepted source response bytes |
| `ADVERSARYFLOW_NODE_MAX_ATTEMPTS` | `3` | Total attempts per model node |
| `ADVERSARYFLOW_RETRY_BASE_DELAY` | `0.25` | Exponential retry base seconds |
| `ADVERSARYFLOW_FACTUALITY_THRESHOLD` | `1.0` | Required supported-claim ratio |
| `ADVERSARYFLOW_FAIL_ON_FACTUALITY` | `true` | Block packaging when evaluated claims fail |
| `ADVERSARYFLOW_REQUIRE_GROUNDING` | `true` | Require a supported technique for TTP-based live runs |
| `ADVERSARYFLOW_STORE_DIR` | `.adversaryflow` | Durable run/cache root |
| `ADVERSARYFLOW_SOURCE_CACHE_TTL` | `86400` | Source URL freshness seconds; `0` always refetches |

Boolean values accept `1`, `true`, `yes`, or `on` as true, case-insensitively.
Other values are false. Invalid numeric configuration is rejected before generation.

## Expert automation patterns

### Repeatable non-interactive request creation

```bash
adversaryflow init --output request.json --actor "Example Actor" --objective "Validate identity response" --environment "Isolated Lab" --mode emulation_plan --test-asset LAB-01
adversaryflow validate-request --request request.json
```

### Hermetic research run

Disable reuse and durable storage while retaining explicit outputs:

```bash
adversaryflow generate --request request.json --output artifacts/scenario.md --no-cache --no-store --demo
```

### CI smoke test

```bash
python -m pip install -e '.[dev]'
python -m ruff check src tests
python -m ruff format --check src tests
python -m pytest -q
adversaryflow generate --request examples/apt29_request.json --output reports/ci-demo.md --store-dir .test-artifacts/store --demo
```

### Shell completion

Typer exposes completion commands:

```bash
adversaryflow --show-completion
adversaryflow --install-completion
```

Review the generated shell modification before installing it on managed systems.

### Exit behavior

| Code | Meaning | Observed examples |
|---:|---|---|
| `0` | The command did what it said | any successful `generate`, `doctor --demo`, `storage verify` |
| `1` | The command ran and the answer was "no" | `doctor` with incomplete configuration; `doctor --check-network` failing; `storage verify` finding a hash mismatch; `tasks.py` on Python older than 3.11 |
| `2` | The command was asked for something invalid and did not run | unreadable or schema-invalid `--request`; `--format` outside `markdown`/`html`; `--kind`/`--mode` outside their enums; `export-schema`/`init` refusing to overwrite without `--force`; `storage verify` on an unknown run ID; an unwritable output or store directory |

The distinction between `1` and `2` matters in pipelines: `2` means nothing was
attempted and retrying will not help, while `1` may reflect a transient
provider or network condition.

Automation should branch on exit codes and parse the JSON trace, never on
terminal output. Rich wraps and colorizes to terminal width, so human-readable
lines break at different points depending on `COLUMNS`.

Both the output directory and the store directory are preflighted for
writability before any provider call, so a permission problem costs `2` and zero
model calls rather than failing after a full generation.

## Usage troubleshooting

### Configuration is incomplete

Run `adversaryflow doctor`. Confirm `.env` is in the current working directory,
not merely beside the installed package. Exported environment variables override it.

### Request validation fails

Run `validate-request`, inspect the full field path, and compare against the
exported schema. Non-tabletop requests need a designated test asset; ad hoc
requests need `ad_hoc_scenario`.

### Grounding policy fails

The system could not retain a source-supported technique. Check Brave credentials,
allowlisted results, publication dates, the local ATT&CK bundle, and the trace's
retrieval section. Do not disable grounding merely to force a production report.

### Factuality policy fails

Inspect unsupported claims and citation edges in the trace. Research mode can set
`ADVERSARYFLOW_FAIL_ON_FACTUALITY=false`, but the report remains failed and must
not be represented as verified.

### A cached run behaves differently than expected

Inspect trace cache keys and counters. Use `--refresh-sources`, `--refresh-nodes`,
or `--no-cache` for a controlled comparison. Prompt, schema, provider/model, or
input changes automatically invalidate node keys.

### Stored-run verification fails

Treat a missing artifact or hash mismatch as an integrity failure. Preserve the
directory for investigation, compare against backups, and regenerate under a new
run ID rather than editing the manifest.

### The CLI shows a traceback

Preserve the trace and exact command with secrets removed. Run `doctor`, confirm
filesystem permissions for the report and store directories, and rerun in demo
mode to separate provider/network issues from local installation issues.
