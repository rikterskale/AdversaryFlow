# Export formats

AdversaryFlow exports a portable execution kit, command-free purple-team
reports, and schema-versioned planning records. Execution kits and human
reports are serialized only after the submitted plan is rebound to the local
bounded catalog. JSON preserves the submitted schema 2.0 record as the
canonical machine-readable source. The web service never executes a command.

## Operator execution kit

For Windows, Linux, or macOS plans, **Download <platform> execution kit**
creates one ZIP containing:

- an RFC 4180 UTF-8 CSV with one row per ordered plan-step occurrence;
- a self-contained `.ps1` or `.sh` runner containing the matching plan; and
- `AdversaryFlow-exercises.py` when the plan includes bounded synthetic
  exercises.

The service **rebinds every technique to the live catalog** before the ZIP is
written. Client-supplied command text is discarded, so an exported kit cannot
carry an operator- or attacker-supplied payload under an AdversaryFlow name.

The CSV and runner are integrity-bound with SHA-256. Keep every file in the ZIP
together when handing the kit to an operator. The runner refuses to start if the
CSV is missing or has changed. The CSV is for human review; the runner uses its
own embedded plan, avoiding fragile CSV parsing on the destination machine.

Direct catalog commands need no AdversaryFlow installation, Python runtime, or
network connection on the destination. Bounded synthetic steps invoke the
bundled exercise script and therefore need Python 3.10+ beside the kit; they
still do not require an AdversaryFlow install or network access. PowerShell
kits require Windows PowerShell 5.1 or newer. Linux and macOS kits require Bash
and standard utilities (`base64`, `sha256sum` or `shasum`, `awk`, `date`, and
`mktemp`).

Before every supported step, the runner displays the technique, risk,
prerequisites, expected output, expected telemetry, and exact command. The
operator must choose run, edit, skip, or abort. Edited commands require a reason
and a second approval. Cleanup is separately approved. Command execution and
detection assessment are recorded independently.

The runner creates an `AdversaryFlow-results-<run-id>` directory beside itself
containing:

- `execution-report.html` and `execution-report.md`;
- `execution-summary.json` and `execution-results.csv`;
- append-only `evidence-events.jsonl`;
- original and effective command files;
- separate stdout and stderr logs; and
- `SHA256SUMS` covering the returned evidence bundle.

`execution-summary.json` conforms to
`schemas/adversaryflow-execution.schema.json`. Operator and target strings are
base64-encoded in that small cross-shell summary; the human reports and results
CSV display their decoded values.

The AdversaryFlow web service generates these files but never executes their
commands or requires the destination runner to call back to the service.

## Purple-team engagement reports

On the Export step, select **Generate report**. The page shows an explicit
generating state, then embeds the returned self-contained HTML in a sandboxed
preview. A failed request leaves an error and **Retry report generation**
control in place. Once the preview is ready, the HTML, PDF, and JSON download
buttons become available.

The CSRF-protected `POST /api/report/{format}` endpoint accepts `html`, `pdf`,
or `json`. HTML and PDF contain:

- actor identity and aliases, domains, platform, authorized scope, plan time,
  operator, target, and the observed execution window;
- the ordered technique occurrences with ATT&CK IDs and tactics;
- curated/fallback/support counts plus exact command-outcome and detection-
  outcome counts;
- expected telemetry and any bounded-exercise telemetry-acceptance contract;
- ATT&CK data-source and detection guidance carried by the plan's STIX-derived
  technique records;
- Sigma rule labels and HTTPS references only when a catalog record explicitly
  supplies them;
- command outcome, detection result, notes, cleanup status, run ID, timestamps,
  exit code, output/receipt hashes, evidence source, and telemetry references;
  and
- categorized catalog, execution, detection, and telemetry coverage gaps.

### Mapping provenance

| Report field | Source |
| --- | --- |
| ATT&CK ID, tactic, actor, domains, platform, scope, operator, target | Existing schema 2.0 plan export |
| Expected telemetry, fidelity, curated/fallback status, telemetry acceptance | Server-side command catalog after catalog rebinding |
| ATT&CK data sources and detection guidance | `data_sources` and `detection` already exported from the loaded STIX technique (`x_mitre_data_sources` and `x_mitre_detection`) |
| Sigma/detection-rule references | Only an explicit catalog reference; none is inferred from a technique ID or detection paragraph |
| Outcomes and evidence | The technique's schema 2.0 `execution` record |
| Coverage gaps | Deterministic counts and findings computed from the fields above |

The current catalog does not declare a Sigma-reference field. Reports
therefore emit no Sigma links and mark **Sigma mapping** as a gap. This is not a
claim that a community rule does not exist. Adding such a link requires an
explicit reviewed catalog field; report generation never searches for rules or
contacts the network.

Reports omit command bodies, cleanup commands, and any executable content.
The self-contained HTML report escapes all plan text and carries a restrictive
content-security policy. The dependency-free PDF is rendered from that HTML,
is paginated, and includes the plan digest and ATT&CK data version for
provenance. The plan's own `generated` value is used instead of a new report
clock, so the same plan and catalog produce the same bytes. Report generation
does not refresh ATT&CK data, search for rules, run a kit, or contact a target.

Missing evidence does not make report generation fail. An incomplete
engagement record remains a valid report with **Not recorded**, **Not run**,
**Not assessed**, or the applicable coverage gap shown explicitly.

JSON remains the canonical machine-readable plan and evidence record. The
`json` report endpoint serializes that submitted record without creating a
parallel report schema. HTML/PDF are human-facing views derived from it, not
new schema versions.

### Evidence limitation

A digest-verified bounded-exercise receipt proves only that the self-reported
receipt has not changed since its digest was calculated. It does **not**
independently prove that the technique ran or that a control detected it.
Correlate the receipt's run ID, timestamps, event types, and hashes with
independently collected endpoint or SIEM telemetry before treating execution
or detection as verified. See [Independent telemetry](TELEMETRY.md).

## JSON

Schema 2.0 JSON exports conform to the checked-in
schemas/adversaryflow-plan.schema.json contract and include:

- between 1 and 32 non-empty stages, with no more than 2,000 techniques per
  stage or 4,000 technique records across the plan;

- tool, schema, and ATT&CK data versions;
- actor, domains, platform, stage, network/admin, and risk scope;
- structured command safety metadata and exact-platform support;
- operator and target context;
- passed, failed, skipped, or not-run command outcomes, recorded separately
  from detection results (not assessed, alerted, silent, blocked, not
  instrumented);
- unique run IDs, start/completion timestamps, exit codes, evidence notes,
  cleanup verification, stdout/stderr hashes, receipt digests, evidence-source
  classification, and endpoint/SIEM references.

The 146 bounded synthetic exercises emit digest-protected JSON receipts that
can be verified and imported from the plan screen. This verifies receipt
integrity, not independent execution; use endpoint or SIEM references to record
that stronger corroboration.

The welcome screen can resume a schema 2.0 export. Imported commands are
treated as untrusted high-risk content and require acknowledgment before copy.
The format is AdversaryFlow-native; VECTR and Caldera conversion is not included.

## Markdown

Markdown includes scope, command outcomes, detection results, evidence,
commands, notes, and cleanup. It is intended for human review and ticketing
rather than automated ingestion.

## Runbook

Runbooks use REM comments for Windows and # comments for Linux/macOS. Every
command is emitted as a commented `COMMAND:` line, so the artifact cannot be
executed as a script without deliberate operator editing.
Downloads retain a .txt suffix so they are review artifacts rather than
directly executable scripts. Unsupported or safety-restricted entries are
comments only. Cleanup remains an explicit manual action.
