# Architecture

AdversaryFlow separates planning, safety validation, local simulation, lifecycle persistence, and user guidance.

```mermaid
flowchart LR
  CLI[CLI or local manager] --> RoE[RoE and catalog validation]
  RoE --> Draft[Offline or provider-backed draft]
  Draft --> Store[Local campaign artifacts]
  Store --> Review[Inspect and decision records]
  Review -->|Named RoE approver plus confirmation| Sim[Fixed local emulation]
  Sim --> Report[Telemetry gap and campaign reports]
```

`manager.py` exposes a loopback-only HTTP workspace. `provider.py` validates offline and OpenAI-compatible configuration; `profiles.py` persists non-secret profile metadata. `workflow.py` persists drafts, verifies integrity, enforces approval, and runs the synthetic harness. `emulation.py` permits only `none` and `loopback` network scope. `reports.py` writes Markdown and HTML campaign reports.

The browser manager can approve and run only the fixed `local-synthetic` adapter after exact RoE-approver identity, campaign-specific typed confirmation, and integrity checks. `local-behavioral` and `idpt-local` execution remain CLI paths. Campaign roots and IDs are constrained so lifecycle operations remain within the configured local root.

See the module guides for [campaign workflow](modules/campaign-workflow.md), [local manager](modules/local-manager.md), [providers](modules/providers.md), [diagnostics](modules/diagnostics-and-support.md), [reports](modules/reports.md), and [safety/emulation](modules/safety-and-emulation.md).
