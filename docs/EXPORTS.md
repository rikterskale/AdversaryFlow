# Export formats

AdversaryFlow exports the current scoped plan in three formats.

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
