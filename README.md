# AdversaryFlow v0.2.1

AdversaryFlow is a threat-informed red team scenario generator for authorized, collaborative purple-team exercises. It resolves a threat actor, builds a claim-level cited TTP dossier, adapts observed behaviors to the target environment and Rules of Engagement (RoE), and produces safe exercise equivalents rather than literal destructive or criminal actions.

Version 0.2.1 is the GitHub-ready AdversaryFlow release, including the renamed package namespace, CLI, environment variables, Docker entrypoint, documentation, CI, and repository governance files.

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
adversaryflow generate \
  --request examples/ad_hoc_request.json \
  --output reports/ad_hoc_scenario.md \
  --demo
```

Ad hoc reports intentionally show no grounded TTP dossier unless you explicitly include supported technique mappings in the request.

## Quick start: deterministic demo

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env  # optional: edit only for live providers/search

adversaryflow generate \
  --request examples/apt29_request.json \
  --output reports/apt29_scenario.md \
  --demo
```

Demo mode validates the 12-node DAG, strict schemas, trace generation, safety policy, claim-evidence evaluator, and renderer without external services. It intentionally emits no live actor claims, so its factuality status is reported as N/A rather than 100% verified.

Run tests and lint:

```bash
pytest -q
ruff check src tests
ruff format --check src tests
```

## Production configuration

### 1. Model provider

The included model adapter works with OpenAI-compatible chat-completion APIs that support JSON-object output:

```bash
export ADVERSARYFLOW_LLM_BASE_URL="https://your-provider.example/v1"
export ADVERSARYFLOW_LLM_API_KEY="..."
export ADVERSARYFLOW_LLM_MODEL="your-model"
```

Every node receives its exact JSON Schema in the system prompt. Returned JSON is validated locally with Pydantic. Invalid output is retried with a repair context containing the previous response and validation errors.

### 2. Brave Search

```bash
export ADVERSARYFLOW_SEARCH_PROVIDER="brave"
export ADVERSARYFLOW_BRAVE_API_KEY="..."
```

The adapter calls the Brave Web Search endpoint and adds `site:` restrictions for the configured allowlist. Search syntax is only a retrieval optimization: every result is independently rejected unless its HTTPS URL is allowlisted. Redirect destinations are checked again during fetch.

To intentionally disable live search:

```bash
export ADVERSARYFLOW_SEARCH_PROVIDER="null"
```

### 3. Run

```bash
adversaryflow generate \
  --request examples/apt29_request.json \
  --output reports/apt29_scenario.md \
  --attack-bundle data/enterprise-attack.json
```

### CLI options

| Option | Purpose |
|---|---|
| `--request PATH` | Required scenario request JSON file. |
| `--output PATH` | Markdown report path; the trace is written next to it with `.trace.json`. |
| `--demo` | Use the deterministic demo provider and disable live search. |
| `--search-provider brave|null` | Override `ADVERSARYFLOW_SEARCH_PROVIDER` for the run. |
| `--attack-bundle PATH` | Optional pinned Enterprise ATT&CK STIX bundle for local actor/TTP grounding. |

For local configuration, copy `.env.example` to `.env` and export the variables needed by your shell or process manager before running the CLI.

## Configuration reference

| Variable | Default | Purpose |
|---|---:|---|
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

- a Markdown scenario report;
- a `.trace.json` audit record containing node attempts, retrieval statistics, local ATT&CK context, citation graph, and factuality result.

The renderer intentionally emits operator-level summaries, evidence requirements, telemetry expectations, stop conditions, and cleanup—not exploit code or destructive commands.

## Remaining production hardening

1. Persist source documents, hashes, and node state in a durable content-addressed cache.
2. Add provider failover and per-node token/cost budgets.
3. Sign reproducibility bundles and source manifests.
4. Add reviewer identity, approval state, and immutable release records.
5. Add an evaluation corpus for actor precision/recall, citation entailment, safety, realism, and environment fit.
6. Add ATT&CK Navigator export and optional execution-framework export behind separate approval policies.

## Publish to GitHub

The repository includes CI, issue forms, a pull-request template, contribution guidance, an example environment file, and a security policy. See [`GITHUB_SETUP.md`](GITHUB_SETUP.md) for command-line and web-upload instructions.
