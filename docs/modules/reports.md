# Reports and artifacts

Campaign drafts are stored under `artifacts/campaigns` by default. Each draft directory contains `draft.json` and `metadata.json`; approval, rejection, and cancellation records are added when those decisions occur.

An approved local synthetic emulation writes a run directory under `artifacts/runs` by default. It includes `progress.json`, `events.jsonl`, `manifest.json`, `audit.jsonl`, a copy of the draft, and `telemetry-gap-report.json`.

After a campaign completes, AdversaryFlow writes `campaign-report.md` and `campaign-report.html` in the campaign directory. The reports include campaign scope and status, plan hash, approval record, synthetic behavior result, expected and observed telemetry counts, detection gaps, and a safety note that production-log validation remains separate.

The local manager may display an existing HTML campaign report but does not create approval or emulation results. See [campaign-workflow.md](campaign-workflow.md) and [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md).
