# Local manager

Run `adversaryflow manager --open` to start the guided local workspace. By default it binds to `127.0.0.1:8787`; permitted hosts are `127.0.0.1`, `localhost`, and `::1`.

The manager loads the active RoE and safe catalog, presents the approved targets, and creates an offline RoE-validated draft. It can show campaign summaries and details, display local reports, and record rejection or cancellation decisions.

The manager cannot use a hosted provider, approve a campaign, run emulation, bind to a non-loopback interface, or provide an arbitrary command runner. It displays copyable CLI commands for actions that remain CLI-only.

See [../USAGE.md](../USAGE.md) for the walkthrough and [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for local-manager recovery.
