# Local manager

Run `adversaryflow manager --open` to start the guided local workspace. By default it binds to `127.0.0.1:8787`; permitted hosts are `127.0.0.1`, `localhost`, and `::1`.

The manager loads the active RoE and safe catalog, presents the approved targets, and creates an offline RoE-validated draft. Its browser-local setup checklist remembers when scope loaded, the health check passed, a draft was saved, and a campaign was reviewed. Health-check failures are summarized in plain language with copyable remediation commands. It also shows novice-friendly campaign labels such as “Needs approval” and “Complete”, displays local reports, and records rejection or cancellation decisions.

The manager cannot use a hosted provider, approve a campaign, run emulation, bind to a non-loopback interface, or provide an arbitrary command runner. It displays copyable CLI commands for actions that remain CLI-only.

See [../USAGE.md](../USAGE.md) for the walkthrough and [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for local-manager recovery.
