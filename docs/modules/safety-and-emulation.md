# Safety and emulation

Rules of Engagement require an engagement name, operator name, approver name, and approved targets. RoEs must remain dry-run. A target is permitted only when it is approved and not excluded.

Run `adversaryflow adapter status` to inspect the registered adapter, contract version, allowed scopes, and compatibility with the local catalog. This is read-only; `adversaryflow doctor` includes the same readiness check.

Catalog abilities must declare expected telemetry and `writes_only_run_root: true`. Their network scope is restricted to `none` or `loopback`.

Approval validates the AI draft against the RoE and catalog and accepts only the approver named in the RoE. A rejected decision cannot start local emulation.

Local emulation preflights the fixed adapter against the complete reviewed ability set before it runs. The run manifest records that versioned preflight, the adapter name, selected abilities, simulation-only boundary, permitted network scopes, and an event hash. It writes only local run artifacts and uses an engine-owned loopback sink for the fixed synthetic marker. If preflight or the adapter fails, progress and manifest records are marked failed and an audit event is written; the failure does not fall back to another adapter or execute a command. It records synthetic events and expected telemetry; production-log validation remains separate.

See [campaign-workflow.md](campaign-workflow.md) and [../ARCHITECTURE.md](../ARCHITECTURE.md).
