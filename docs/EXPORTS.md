# Export formats

AdversaryFlow exports a portable execution kit plus three planning formats.

## Operator execution kit

For Windows or Linux plans, **Download operator execution kit** creates one ZIP
containing exactly two files:

- an RFC 4180 UTF-8 CSV with one row per ordered plan-step occurrence; and
- a self-contained `.ps1` or `.sh` runner containing the matching plan.

The CSV and runner are integrity-bound with SHA-256. Keep them together when
handing the kit to an operator. The runner refuses to start if the CSV is
missing or has changed. The CSV is for human review; the runner uses its own
embedded plan, avoiding fragile CSV parsing on the destination machine.

The destination requires no AdversaryFlow installation, Python runtime, or
network connection. PowerShell kits require Windows PowerShell 5.1 or newer.
Linux kits require Bash and standard Linux utilities (`base64`, `sha256sum`,
`awk`, `date`, and `mktemp`).

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

## JSON

Schema 2.0 JSON exports conform to the checked-in
schemas/adversaryflow-plan.schema.json contract and include:

- tool, schema, and ATT&CK data versions;
- actor, domains, platform, stage, network/admin, and risk scope;
- structured command safety metadata and exact-platform support;
- operator and target context;
- passed, failed, skipped, or not-run outcomes;
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

Markdown includes scope, outcomes, evidence, commands, notes, and cleanup. It
is intended for human review and ticketing rather than automated ingestion.

## Runbook

Runbooks use REM comments for Windows and # comments for Linux/macOS. Every
command is emitted as a commented `COMMAND:` line, so the artifact cannot be
executed as a script without deliberate operator editing.
Downloads retain a .txt suffix so they are review artifacts rather than
directly executable scripts. Unsupported or safety-restricted entries are
comments only. Cleanup remains an explicit manual action.
