# Local manager

Run `adversaryflow manager --open` to start the guided local workspace. By default it binds to `127.0.0.1:8787`; permitted hosts are `127.0.0.1`, `localhost`, and `::1`.

The manager loads the active RoE and safe catalog, presents the approved targets, and creates an offline RoE-validated draft. “Create safe example draft” uses the active RoE target with fixed defensive values so a new operator can inspect a concrete local example without replacing their form entries; it does not approve or run it. Its browser-local setup checklist remembers when scope loaded, the health check passed, a draft was saved, and a campaign was reviewed. Health-check failures are summarized in plain language with copyable remediation commands. Campaign review starts with a plain-language safety summary explaining reviewed local actions, explicitly excluded actions, and why the draft is permitted. It also shows novice-friendly campaign labels such as “Needs approval” and “Complete”, displays local reports, and records rejection or cancellation decisions.

The manager can approve and run a reviewed campaign only when the RoE-named approver enters their exact name, types the campaign-specific confirmation, and the saved draft, RoE, and catalog integrity checks all pass. It uses the fixed local-synthetic adapter and report flow. The browser approval path cannot use a hosted provider, `local-behavioral`, or `idpt-local`; it cannot bind to a non-loopback interface or provide an arbitrary command runner.

The workspace also exposes non-secret provider profile setup, active-profile and policy readiness, a MITRE ATT&CK dry-run planner, redacted support-bundle creation, searchable campaign history, side-by-side campaign comparison, and a release-readiness dashboard. Provider credentials are never entered into or stored by the browser: configure the selected profile's credential environment variable through a shell or secret manager. The ATT&CK planner fetches the official HTTPS bundle and produces a plan only; it does not create or execute a campaign.

Additional workspace tools provide actor-profile planning and runs, benign-procedure runs and assessment, CTID fixture creation and assessment, detection-mapping guidance, the actor-to-detection coverage dashboard, archive search, campaign tags, owner and retention controls, executive-summary Markdown/PDF export, and a validated RoE editor with version history. These operations remain local; their individual confirmation and scope boundaries are shown in the workspace before the action is submitted.

## Additional workspace workflows

The additional tools are available from the manager interface rather than as top-level CLI subcommands:

- Actor validation profiles select only pre-registered benign fixtures and/or fixed benign procedures. A profile can be planned and run locally; its run records a retest relationship when one is supplied.
- Benign procedures create run-owned evidence, support offline assessment of observed procedure IDs, and provide cleanup limited to the run-owned `work` directory.
- CTID fixture workflows create synthetic JSONL fixtures, record observed fixture IDs, and write a local detection-gap report plus training timeline. The fixture bundle is not a production event source.
- Archive search matches campaign ID, actor, objective, and tags. Tags are normalized to lowercase; ownership and retention controls are stored in campaign metadata.
- Executive-summary export writes Markdown and PDF files beneath `artifacts/exports` by default.
- The RoE editor validates the replacement RoE before saving and records the previous YAML snapshot beneath `artifacts/roe-history`.

These workflows do not add arbitrary commands, remote execution, credential access, cloud changes, external network contact, or destructive target actions.

## Local API surface

The manager exposes a local JSON API on the same loopback-only server as the workspace. It is not a remote service. The read-only GET resources are:

| Resource | Purpose |
|---|---|
| `/api/health` | Report that the local manager is running. |
| `/api/context` | Return the active RoE scope and catalog context. |
| `/api/provider` | Return redacted provider readiness. |
| `/api/provider/compatibility` | Return provider compatibility information. |
| `/api/operator-readiness` | Return RoE, capability, and adapter readiness. |
| `/api/learning` | Return catalog learning context for a technique. |
| `/api/detection-mappings` | Return defensive detection-mapping guidance. |
| `/api/ctid-fixtures` | List the fixed CTID-fixture catalog. |
| `/api/actor-profiles` | List actor validation profiles. |
| `/api/benign-procedures` | List fixed benign procedures. |
| `/api/coverage` | Return the actor-to-detection coverage dashboard. |
| `/api/release` | Return read-only release artifact, catalog-manifest, SBOM, and signature readiness. |
| `/api/safety` | Return the local-only safety state, including kill-switch status and dry-run boundary. |
| `/api/safety/kill` and `/api/safety/clear` | Explicitly set or clear the local approval kill switch; this blocks new campaign approvals while active. |
| `/api/archive` | Search campaigns by query or tag. |
| `/api/roe` | Read the validated RoE and recent history. |
| `/api/campaigns` | List saved campaigns and portfolio status. |
| `/api/campaigns/{campaign_id}` | Inspect one saved campaign. |
| `/api/campaigns/{campaign_id}/report` | Read an existing HTML campaign report. |
| `/api/actor-profiles/{name}` | Read one actor profile. |
| `/api/actor-profiles/{name}/plan` | Plan one actor profile. |

The POST actions are:

| Action | Purpose |
|---|---|
| `/api/doctor` and `/api/doctor/fix` | Run diagnostics, optionally creating local artifact folders. |
| `/api/support-bundle` | Create a redacted support bundle. |
| `/api/demo` | Run the typed-confirmation local synthetic demo. |
| `/api/plan` | Fetch the official ATT&CK bundle and create a dry-run plan. |
| `/api/provider/profiles`, `/api/provider/use`, `/api/provider/allow`, `/api/provider/remove` | Manage non-secret provider profiles and policy approval. |
| `/api/provider/test` | Send one confirmed hosted planning request. |
| `/api/roe` | Validate and save an RoE, retaining the previous YAML snapshot. |
| `/api/archive/tags` and `/api/archive/controls` | Update campaign tags, owner, and retention metadata. |
| `/api/exports/executive-summary` | Write a Markdown and PDF executive summary. |
| `/api/ctid-fixtures` and `/api/ctid-fixtures/assess` | Create and assess local CTID-fixture bundles. |
| `/api/actor-profiles` and `/api/actor-profiles/{name}/run` | Save and run fixed actor validation profiles. |
| `/api/benign-procedures/run`, `/api/benign-procedures/assess`, `/api/benign-procedures/cleanup` | Run, assess, and clean up fixed benign procedures. |
| `/api/campaigns`, `/api/campaigns/provider` | Create offline or provider-backed review drafts. |
| `/api/campaigns/{campaign_id}/approve` | Approve and run local-synthetic emulation after exact confirmation. |
| `/api/campaigns/{campaign_id}/reject` and `/api/campaigns/{campaign_id}/cancel` | Record campaign decisions. |
| `/api/campaigns/{campaign_id}/reset` | Permanently remove a saved campaign after typed confirmation. |

Request bodies are JSON. Campaign approval requires the RoE approver name and `APPROVE {campaign_id}` confirmation. Campaign reset requires `RESET {campaign_id}`. Provider-profile removal requires `REMOVE {name}`. The manager keeps all writes inside the configured local workspace.

The query parameters are `technique` on `/api/learning` and `/api/detection-mappings`, and `q` plus `tag` on `/api/archive`. They filter the read-only responses; omitted parameters return the unfiltered local result.

## Data formats

The packaged ability catalog uses `ADVERSARYFLOW-ABILITY-CATALOG-1`. Each ability declares an ID, version, ATT&CK technique, platform, fidelity, expected telemetry, run-root safety, network scope, cleanup action, and (for executable catalogs) a fixed execution action. The operator cannot provide commands through the catalog.

Fixed benign procedures use `ADVERSARYFLOW-BENIGN-PROCEDURES-1`. Each procedure declares an ID, technique, name, local action, source, expected detection, and cleanup. Procedure runs write only run-owned evidence.

Offline telemetry uses `ADVERSARYFLOW-TELEMETRY-1`; its correlation fields and vendor aliases are documented in [DETECTION_VALIDATION.md](../DETECTION_VALIDATION.md). CTID-fixture bundles are synthetic local evidence and are not production event sources.

All versioned schemas and artifact filenames are listed in [../SCHEMAS.md](../SCHEMAS.md).

See [../USAGE.md](../USAGE.md) for the walkthrough and [../TROUBLESHOOTING.md](../TROUBLESHOOTING.md) for local-manager recovery.
