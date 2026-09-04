# Export formats

AdversaryFlow exports the current scoped plan in three formats.

## JSON

JSON exports conform to [`schemas/adversaryflow-plan.schema.json`](../schemas/adversaryflow-plan.schema.json) and include:

- schema, tool, and ATT&CK data versions;
- selected domains and platform;
- runnable and unsupported counts;
- only completion records in the current scope;
- an explicit `supported` flag for every technique.
- `command_source` and `command` fields for each exported technique.

The format is AdversaryFlow-native. Product-specific VECTR or Caldera conversion is not currently included.

## Markdown

The Markdown report distinguishes runnable and unsupported techniques and records the selected platform and catalog coverage.

## Runbook

Runbooks use `REM` comments for Windows and `#` comments for Linux/macOS. Downloads retain a `.txt` suffix so they are review artifacts rather than directly executable scripts. Entries with no exact-platform command are emitted as comments only.

Cleanup metadata is emitted as an explicit `MANUAL CLEANUP` comment; AdversaryFlow does not execute it.
