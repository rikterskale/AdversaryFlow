# AdversaryFlow v0.2.1 Architecture

## 1. Product boundary

AdversaryFlow produces exercise plans, evidence requirements, telemetry expectations, injects, and safe operator action summaries. It is not an autonomous intrusion platform. Any future export to an execution framework must be a separate capability protected by an explicit reviewer approval gate.

## 2. Retrieval strategy

### Stable core

Use a pinned local ATT&CK STIX bundle for actor identity, aliases, group-to-technique relationships, software, and campaign relationships. Persist the ATT&CK release, source URL, retrieval timestamp, file checksum, and parser version.

### Live edges

Use live allowlisted retrieval for current vendor detections, telemetry prerequisites, product rule names, newly published advisories, first-party reports, Atomic Red Team content, and Caldera references.

The production search path has four controls:

1. Query-time `site:` restrictions generated from the configured domain allowlist.
2. Post-search HTTPS and hostname allowlist filtering.
3. Redirect-by-redirect scheme, hostname, and public-IP validation.
4. Response-size limits, content hashing, extraction status, and content-type handling.

Search syntax is never treated as a security boundary.

### Extraction

Validated sources are converted into normalized text and deterministic chunks. v0.2 supports HTML, plain text, JSON/XML-like text, and PDF text extraction. Each chunk has a source URL, ordinal, SHA-256 hash, and stable chunk ID.

## 3. Typed orchestration

All 12 nodes have a dedicated strict Pydantic output model. Extra keys are forbidden. The model receives the node JSON Schema in its system prompt, and AdversaryFlow validates the response locally.

The successful path remains 12 calls. The node runner can add bounded repair attempts only when a node returns invalid output or the provider fails.

Each trace records:

- schema name;
- attempt count;
- attempt status;
- duration;
- raw output;
- validation/provider error;
- parsed output.

Parallel nodes do not mutate shared state. Citation graph updates happen after explicit join points.

## 4. Claim graph

A factual claim is a first-class object containing text, category, confidence, technique IDs, source URLs, and optional model-selected supporting excerpts.

The citation graph contains:

- `CitationSource` nodes for validated documents;
- `CitationClaim` nodes for extracted and final claims;
- `CitationEdge` relationships containing the supporting excerpt, chunk ID, support method, and lexical support score.

Supported methods are:

- `model_excerpt`: the model selected a passage that is still scored against the claim;
- `lexical_match`: AdversaryFlow selected the best matching extracted chunk;
- `local_attack`: the pinned ATT&CK relationship supplied authoritative support.

Final reports preserve the graph and display claim-level evidence rather than only a source list.

## 5. Factuality evaluator

The deterministic evaluator audits:

- final actor-specific claims;
- every technique in the synthesized dossier;
- every technique ID retained in the selected exercise path.

A claim is supported when it has a validated citation edge above the configured support threshold or an exact technique relationship in the pinned ATT&CK bundle. The evaluator emits per-claim findings, support score, citation coverage, supported count, unsupported list, and final pass/fail.

By default, unsupported actor claims block report generation. This behavior can be changed for research runs with `ADVERSARYFLOW_FAIL_ON_FACTUALITY=false`, but the failed result remains visible in the report and trace.

## 6. Safety architecture

Prompt constraints are guidance, not the security boundary. Enforcement remains layered:

1. request and RoE validation;
2. retrieval allowlist and SSRF resistance;
3. strict node schemas;
4. deterministic safety policy;
5. safe-equivalent requirements;
6. explicit stop conditions and cleanup;
7. claim-level factuality evaluation;
8. human approval before execution-oriented export;
9. complete audit trail.

## 7. Failure behavior

### Search failure

Individual query failures are recorded and generation can continue with other live queries or the local ATT&CK bundle. If grounded actor claims cannot be supported, the factuality gate blocks the result.

### Source failure

Invalid, oversized, private-address, redirect-escape, unreachable, or unextractable sources are excluded from model grounding. Unused failures are warnings; cited-source failures cause source-validation or factuality failure.

### Model failure

Provider and schema failures use exponential backoff and a repair context. After the configured maximum attempts, the run stops with a node-specific error and the complete attempt trace.

### Factuality failure

Unsupported claims are never silently converted into facts. Strict mode stops packaging; non-strict research mode packages the report with a failed factuality status and detailed findings.

## 8. Reproducibility

The v0.2 trace preserves the retrieval queries, source hashes, local ATT&CK context, validated documents used for grounding, node schemas and attempts, citation graph, factuality result, and final safety decision. A future durable cache should key source bodies by content hash and node inputs by canonical JSON hash.

## 9. Test coverage

The test suite covers:

- HTTPS/domain allowlisting;
- local ATT&CK resolution and relationships;
- exactly 12 successful demo calls;
- request safety policy;
- schema registry completeness;
- validation-triggered repair calls;
- Brave result post-filtering;
- citation graph creation;
- supported and unsupported factuality decisions.

## 10. Next slices

### Durable grounding

- content-addressed source cache;
- conditional requests and freshness policy;
- signed manifests;
- publication-date extraction and conflict handling.

### Scenario intelligence

- constrained behavior graph and path search;
- environment feasibility adapters;
- detection-rule normalization;
- quality and realism evaluator;
- generated injects grounded in the selected path.

### Workflow and exports

- API and web UI;
- reviewer workflow and release signatures;
- scenario version history;
- ATT&CK Navigator layer export;
- optional Atomic/Caldera export behind a separate approval policy.
