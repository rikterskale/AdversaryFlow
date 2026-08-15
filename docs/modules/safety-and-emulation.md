# Safety and emulation

Rules of Engagement require an engagement name, operator name, approver name, and approved targets. RoEs must remain dry-run. A target is permitted only when it is approved and not excluded.

Run `adversaryflow adapter status` to inspect the registered adapter, contract version, allowed scopes, and compatibility with the local catalog. This is read-only; `adversaryflow doctor` includes the same readiness check.

Catalog abilities must declare expected telemetry and `writes_only_run_root: true`. Their network scope is restricted to `none` or `loopback`.

Approval validates the AI draft against the RoE and catalog and accepts only the approver named in the RoE. A rejected decision cannot start local emulation.

Local emulation preflights the fixed adapter against the complete reviewed ability set before it runs. The run manifest records that versioned preflight, adapter name, selected abilities, execution boundary, permitted network scopes, and an event hash. The synthetic adapter uses only an engine-owned loopback marker. The behavioral adapter uses only code-owned read-only commands. The IDPT adapter requires an exact clean reviewed commit, invokes one fixed scenario, binds a derived IDPT RoE to the approved plan, and verifies the resulting evidence manifest. If preflight or an adapter fails, progress and manifest records are marked failed and an audit event is written; execution never falls back to another adapter. Behavior evidence and expected telemetry are recorded independently from production-log validation.

For `idpt-local`, the fixed scenario is selected by the packaged reviewed registry from the complete ability set. The adapter checks the IDPT checkout and content before Node.js is invoked, constrains all IDPT output to the AdversaryFlow run-owned directory, verifies the returned plan against the reviewed host/technique/ability mapping, and passes IDPT a derived RoE containing the approved plan identity. After execution, the adapter verifies the IDPT run summary and evidence manifest before importing any result event. A valid evidence manifest proves evidence integrity; it does not prove that an EDR/SIEM detected the behavior.

See [campaign-workflow.md](campaign-workflow.md), [../IDPT_INTEGRATION.md](../IDPT_INTEGRATION.md), and [../ARCHITECTURE.md](../ARCHITECTURE.md).
