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

The optional `command.interpreter` field identifies `cmd`, `powershell`, or
`bash`. Existing records without this field default to CMD on Windows and Bash
on Linux/macOS. Windows catalog command lines use CMD; embedded PowerShell
invocations remain explicit. The PowerShell kit supervises the declared shell
and preserves its exit code. Command and cleanup logs are separate, and the
recorded command hashes always describe the final command log files.

Import preserves the saved guardrails and withheld steps. Imported command text
requires explicit review before copying; this does not enable high-risk scope.
Kit rebinding cannot enable a step that the submitted plan withheld.

**Save JSON plan** downloads the current schema 2.0 plan directly in the browser,
including its evidence, without report generation or a working ATT&CK feed.
Changing the command platform or data version saves earlier evidence separately.
Use **Saved evidence from other platforms or data versions** to restore or
download those snapshots. Evidence from an older browser session without a saved
workflow can still be downloaded as an evidence-only backup.

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
- per-technique and plan-level fidelity counts (`direct`, `bounded_synthetic`,
  and `lab_proxy`), with keyed-catalog/fallback provenance shown separately;
- exact command-outcome and detection-outcome counts;
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
| Expected telemetry, fidelity, keyed-catalog/fallback status, telemetry acceptance | Server-side command catalog after catalog rebinding |
| Reviewed Sigma, Elastic, Splunk, or KQL bindings | Verified Ed25519-signed content packs configured by the installation |
| ATT&CK data sources and detection guidance | `data_sources` and `detection` already exported from the loaded STIX technique (`x_mitre_data_sources` and `x_mitre_detection`) |
| Sigma/detection-rule references | Only a verified explicit binding; none is inferred from a technique ID or detection paragraph |
| Outcomes and evidence | The technique's schema 2.0 `execution` record |
| Coverage gaps | Deterministic counts and findings computed from the fields above |

The current command catalog does not declare a Sigma-reference field. Reports
emit no Sigma links unless an active signed content pack supplies an explicit
reviewed binding, and make no per-technique Sigma coverage claim when the
installation has no bindings. This is not a claim that a community rule does
not exist. Report generation never searches for rules or contacts the network.

Reports omit command bodies, cleanup commands, and any executable content.
The self-contained HTML report escapes all plan text and carries a restrictive
content-security policy. The offline Unicode PDF is rendered from that HTML,
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

## Workspace recovery and honest progress

**Begin emulation plan** asks before clearing existing scope, evidence and
snapshots; cancel keeps the entire workspace. **Download workspace recovery
copy** is available throughout the wizard, including when plan export is
invalid or browser storage is full/denied. Storage failures remain visible on
every screen until a successful workspace write, not merely until remount.
Downloads are requests, not confirmation that a file reached disk.

Recovery version 1.0 (`schemas/adversaryflow-workspace.schema.json`) includes
workflow snapshots, archives, procedure citations, evidence, unfinished
telemetry-reference drafts, scope and server engagement identity. Choose it
through **Resume JSON plan**, then confirm replacement. Original crash files
with `saved_workspace` containing a Zustand JSON string remain importable.
Malformed/unsafe state and invalid receipt digests are rejected before any
replacement. Crash reset requires explicit confirmation that the downloaded
copy was opened and checked; clicking a download link alone does not unlock it.

Plan files and API plan artifacts are bounded at **32 MiB of actual UTF-8**,
whole-workspace recovery at **128 MiB**, and individual receipt JSON at **1 MiB**.
The 4,000-procedure/step limits remain. JSON uses pretty formatting when it fits,
otherwise compact formatting without dropping any evidence. The server save
envelope has a separate 1 KiB allowance. Oversized/invalid plans retain their
workspace recovery control; keep the tab open and preserve that copy before
reducing scope or citations.

Telemetry references allow 20 unique values, each at most 500 Unicode
characters. Invalid edits remain recoverable drafts and block plan export;
legacy references are never silently truncated. Notes/detection/cleanup edits
preserve execution operator/target; only new records default to current scope.

**Executed** means passed or failed, never skipped. Optional `summary.reviewed`
includes passed/failed/skipped unique scoped IDs and `summary.skipped` identifies
skips; `marked_run` and each technique's `run` mean executed. Older 2.0/3.0 files
without the optional lists remain accepted; progress is derived from execution
outcomes, not old summary flags. Browser progress counts unique runnable IDs,
while reports intentionally count stage occurrences.

Use **Browse saved engagements** on Welcome to list service records, choose a
revision, download its JSON or restore it with replacement confirmation.
Restoring retains engagement ID/revision; **Save new revision** appends rather
than creating an unrelated engagement. Empty/error states include refresh/retry.

Imported restricted placeholders stay withheld even if a scope guardrail is
enabled. **Reload catalog and review changes** explicitly authenticates and
loads the same actor/domains from the service, keeps the original snapshot and
procedure provenance, preserves current guardrails, and partitions execution
evidence by actor/domains/data version/platform. It returns to Scope for review;
no imported payload executes and exact-platform gaps remain blocked.

All API operations have cancellable deadlines: ordinary requests 30 seconds,
report/kit/refresh/intelligence operations 120 seconds, and setup 15 minutes
overall with bounded individual polls. Timeouts, cancellation, network and
authorization failures remain distinct. Obsolete navigation/startup operations
are cancelled; mutation saves are not blindly retried after uncertain failure.

PDFs package and embed SIL-OFL-licensed Noto Sans SC subsets, with searchable
Chinese, Cyrillic and supported BMP symbols. Unsupported glyphs and non-BMP
emoji appear as explicit searchable `[U+1F50D]`-style code-point markers, never
silent `?` replacements. HTML retains the original Unicode. No OS font or
runtime font download is used; native installs, wheels and containers include
the font and license. The font source/digest is recorded in `NOTICE`.

### Evidence limitation

A digest-verified bounded-exercise receipt proves only that the self-reported
receipt has not changed since its digest was calculated. It does **not**
independently prove that the technique ran or that a control detected it.
Correlate the receipt's run ID, timestamps, event types, and hashes with
independently collected endpoint or SIEM telemetry before treating execution
or detection as verified. See [Independent telemetry](TELEMETRY.md).

Schema 3.0 plan records retain the original bounded-exercise receipt alongside
the compact technique evidence. The service rechecks the receipt digest and
its technique/run identity before accepting an engagement revision. Engagement
run records index the receipt set, per-technique outcomes, and telemetry
references; they do not claim to independently verify the referenced endpoint
or SIEM events.

## JSON

Schema 2.0 JSON exports conform to the checked-in
schemas/adversaryflow-plan.schema.json contract. Schema 3.0 adds accepted
procedure provenance and/or digest-verified receipt payloads under
schemas/adversaryflow-plan-v3.schema.json. Both include:

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
treated as untrusted content and require acknowledgment before copy, while the
saved high-risk, administrator, and network guardrails remain unchanged.
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
