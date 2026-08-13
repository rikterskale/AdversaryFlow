# Architecture

AdversaryFlow separates planning, safety validation, local simulation, lifecycle persistence, and user guidance.

```mermaid
flowchart LR
  CLI[CLI or local manager] --> RoE[RoE and catalog validation]
  RoE --> Draft[Offline or provider-backed draft]
  Draft --> Store[Local campaign artifacts]
  Store --> Review[Inspect and decision records]
  Review -->|CLI approval by named RoE approver| Sim[Local synthetic emulation]
  Sim --> Report[Telemetry gap and campaign reports]
```

`manager.py` exposes a loopback-only HTTP workspace. `provider.py` validates offline and OpenAI-compatible configuration; `profiles.py` persists non-secret profile metadata. `workflow.py` persists drafts, verifies integrity, enforces approval, and runs the synthetic harness. `emulation.py` permits only `none` and `loopback` network scope. `reports.py` writes Markdown and HTML campaign reports.

The browser does not approve or execute campaigns. Campaign roots and IDs are constrained so lifecycle operations remain within the configured local root.
