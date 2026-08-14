# Local manager

Run `adversaryflow manager --open` to start the guided local workspace. By default it binds to `127.0.0.1:8787`; permitted hosts are `127.0.0.1`, `localhost`, and `::1`.

The manager loads the active RoE and safe catalog, presents the approved targets, and creates an offline RoE-validated draft. “Create safe example draft” uses the active RoE target with fixed defensive values so a new operator can inspect a concrete local example without replacing their form entries; it does not approve or run it. Its browser-local setup checklist remembers when scope loaded, the health check passed, a draft was saved, and a campaign was reviewed. Health-check failures are summarized in plain language with copyable remediation commands. Campaign review starts with a plain-language safety summary explaining reviewed local actions, explicitly excluded actions, and why the draft is permitted. It also shows novice-friendly campaign labels such as “Needs approval” and “Complete”, displays local reports, and records rejection or cancellation decisions.

The manager can approve and run a reviewed campaign only when the RoE-named approver enters their exact name, types the campaign-specific confirmation, and the saved draft, RoE, and catalog integrity checks all pass. It uses the same fixed local-synthetic adapter and report flow as the CLI. It cannot use a hosted provider, bind to a non-loopback interface, or provide an arbitrary command runner.

The workspace also exposes non-secret provider profile setup, active-profile and policy readiness, a MITRE ATT&CK dry-run planner, and redacted support-bundle creation. Provider credentials are never entered into or stored by the browser: configure the selected profile's credential environment variable through a shell or secret manager. The ATT&CK planner fetches the official HTTPS bundle and produces a plan only; it does not create or execute a campaign.

See [../USAGE.md](../USAGE.md) for the walkthrough and [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for local-manager recovery.
