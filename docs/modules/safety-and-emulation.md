# Safety and emulation

Rules of Engagement require an engagement name, operator name, approver name, and approved targets. RoEs must remain dry-run. A target is permitted only when it is approved and not excluded.

Catalog abilities must declare expected telemetry and `writes_only_run_root: true`. Their network scope is restricted to `none` or `loopback`.

Approval validates the AI draft against the RoE and catalog and accepts only the approver named in the RoE. A rejected decision cannot start local emulation.

Local emulation writes only local run artifacts and uses an engine-owned loopback sink for the fixed synthetic marker. It records synthetic events and expected telemetry; production-log validation remains separate.

See [campaign-workflow.md](campaign-workflow.md) and [../ARCHITECTURE.md](../ARCHITECTURE.md).
