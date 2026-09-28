# Operations

An explicit feed refresh that cannot download current data returns HTTP 503
with `error: refresh_failed`. Existing cached workflows remain usable and the
browser preserves scope and evidence. Automatic startup loading can still use
a validated stale cache when the upstream feed is unavailable.

After a service restart, the browser renews an expired CSRF token and retries
the rejected mutation once. If the bearer token changed, it opens the API token
dialog again while preserving the plan. Enter the current token and retry the
operation. Saved workflows can be resumed, reviewed, and exported as JSON even
when ATT&CK bootstrap fails.

New operators should start with [Getting started](GETTING_STARTED.md).
This page is the compact service, cache, and diagnostics reference for a
**single-operator loopback lab appliance**. It is not a multi-user production
API; keep the default bind on `127.0.0.1` unless you have read
[SECURITY.md](../SECURITY.md) and opted into `--allow-remote`.

## Service lifecycle

AdversaryFlow starts its HTTP service immediately and loads ATT&CK data in a
background worker. The UI polls GET /api/bootstrap and reports download bytes,
validation, readiness, or a retryable failure.

GET /api/live returns HTTP 200 whenever the process can answer. GET /api/health
returns HTTP 200 only when an ATT&CK index is ready. During startup or failure
health returns 503 with the service phase, cache provenance, request counters,
loaded domain sets, and data versions. A failed API request does not mark the
whole service failed. Every HTTP response includes X-Request-ID; server logs
are structured JSON.

## Configuration

| Setting | CLI | Environment | Default |
| --- | --- | --- | --- |
| Bind address | --host | ADVERSARYFLOW_HOST | 127.0.0.1 |
| Port | --port | ADVERSARYFLOW_PORT | 5000 |
| Cache directory | --cache-dir | ADVERSARYFLOW_CACHE_DIR | Per-user cache |
| Offline mode | --offline | ADVERSARYFLOW_OFFLINE=1 | Disabled |
| Skip startup load | --no-preload | — | Disabled |
| Open browser | --open | — | Source launcher only |
| Remote API token | --api-token | ADVERSARYFLOW_API_TOKEN | Unset |
| Run webhook URL | — | ADVERSARYFLOW_RUN_WEBHOOK_URL | Disabled |
| Run webhook HMAC secret | — | ADVERSARYFLOW_RUN_WEBHOOK_SECRET | Disabled |
| Log level | --log-level | ADVERSARYFLOW_LOG_LEVEL | info |
| Download limit | — | ADVERSARYFLOW_MAX_BUNDLE_BYTES | 128 MiB |

### Run-record webhook

To notify an external system when run evidence is saved with an engagement
revision, configure both `ADVERSARYFLOW_RUN_WEBHOOK_URL` and
`ADVERSARYFLOW_RUN_WEBHOOK_SECRET` before starting the service. The endpoint
must use HTTPS and the secret must contain at least 32 UTF-8 bytes. The service
does not send the event until the revision and outbox row commit together.
Delivery is asynchronous, signed with HMAC-SHA256 over the exact JSON body,
and retried with bounded backoff. Receivers should deduplicate using
`X-AdversaryFlow-Event-ID`; at-least-once delivery means a receiver can see a
duplicate after a timeout.

Events are `run_recorded` notifications with engagement/revision digests, run
summary, receipt-set digest, and telemetry references. Receipt bodies and
secrets are not included. `GET /api/webhook-deliveries` shows recent delivery
status and bounded error class metadata, but not the event payload or endpoint.
Invalid or partial configuration disables delivery; no webhook is sent by
default. The SQLite outbox retains up to 200,000 events and rejects a revision
that would exceed that limit rather than dropping notifications. Keep a
separate backup of the engagement database and configure webhook secrets via
the service environment, not plan fields.

## Network boundary

Loopback is the supported default. A non-loopback bind is refused unless
--allow-remote is present and a non-empty bearer token is supplied with
--api-token or ADVERSARYFLOW_API_TOKEN. An in-app connection dialog requests
the token once and holds it only in session storage; every API route requires
it. Use TLS at an
authenticated reverse proxy, apply host firewall rules, and never expose the
plain HTTP service directly to the internet.

Mutating bootstrap and refresh requests require a same-origin token from
GET /api/session. Refreshes are serialized and rate limited.

## Cache lifecycle and provenance

Each domain has a bundle and metadata sidecar containing the source URL,
ETag, Last-Modified value, SHA-256, byte count, and download/check times.
Downloads have a hard size limit, are validated as STIX bundles, fsynced, and
atomically promoted under a per-domain process lock. A failed refresh can use
an existing stale bundle, but health/cache status marks it stale and records
the refresh error.

Useful commands:

~~~bash
adversaryflow cache-status
adversaryflow cache-refresh --domains enterprise
adversaryflow cache-clear --yes
~~~

cache-clear removes only known AdversaryFlow bundle and metadata files.

## Execution records and recovery

Browser progress is keyed by actor, ATT&CK data version, domains, and command
platform. Outcomes, run IDs, start/completion timestamps, exit codes,
stdout/stderr hashes, receipt digests, endpoint/SIEM references,
operator/target context, notes, and cleanup verification are stored locally.
Exercise receipts are self-reported; correlate their run IDs and timestamps
with the endpoint or SIEM before treating execution as independently verified.
Export a schema 2.0 JSON plan for backup, handoff, or resume. The export screen
uses **Generate report** to produce a sandboxed HTML preview, then enables
command-free HTML/PDF downloads plus the canonical JSON record. Human reports
include telemetry, ATT&CK detection mappings, evidence status, and coverage
gaps; the command catalog has no Sigma-reference field, so reports include
reviewed links only from verified signed content packs and make no per-technique
claim when those packs provide none. Imported commands are marked
unverified and require acknowledgment before copying; saved guardrails remain
unchanged. **Save JSON plan** is also available independently of the service.

Saved revisions, successful exports, and backlog updates are recorded in the
local append-only audit stream. GET `/api/audit-events` verifies the complete
hash chain and pages records; a failed verification returns HTTP 503. Until
identity-provider roles are configured, principal labels are operator text or
`unknown`, not authenticated users. See [Audit log](AUDIT.md).

Do not put secrets in execution notes or exports.

## Diagnostics

Run **adversaryflow doctor** to verify Python and Docker/Compose versions, the
service port, frontend/runtime dependencies, cache integrity and writability,
disk capacity, and official ATT&CK feed reachability. Every check includes a
PASS/FAIL status and a human-readable fix. The GUI status chip exposes the same
report. See the [troubleshooting matrix](TROUBLESHOOTING.md).

For a support request attach:

1. adversaryflow --version;
2. redacted adversaryflow doctor output;
3. the X-Request-ID for a failing request;
4. operating system and browser versions;
5. the affected ATT&CK domain and data version.

For bounded exercise evidence, retain the receipt and independently collected
endpoint/SIEM export. Use `adversaryflow-telemetry collect` for a read-only native
log snapshot and `adversaryflow-telemetry correlate` to enforce the technique's
marker, host, time-window, event-type, and event-count requirements. Collection
does not enable OS auditing; a missing signal fails the gate. See
`docs/TELEMETRY.md`.

## Common failures

- **Setup remains in loading:** inspect download byte progress and JSON logs;
  check proxy, DNS, TLS interception, disk space, and the 128 MiB limit.
- **Invalid cache:** run cache-status, then cache-clear --yes and restart
  online. Preserve the sidecar first if support needs provenance evidence.
- **Offline cache missing:** seed the requested domain online or point
  --cache-dir to a verified cache.
- **Port already in use:** use adversaryflow --port 5050 --open.
- **Refresh conflict:** wait for bootstrap or the existing refresh to finish.
- **Permission denied:** choose a writable per-user --cache-dir.

Waitress handles normal process termination signals. The cache and JSON plan
exports are the only persistent operational state; back them up if required.
