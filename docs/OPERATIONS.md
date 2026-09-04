# Operations

## Service lifecycle

AdversaryFlow starts its HTTP service immediately and loads ATT&CK data in a
background worker. The UI polls GET /api/bootstrap and reports download bytes,
validation, readiness, or a retryable failure.

GET /api/health returns HTTP 200 only when an ATT&CK index is ready. During
startup or failure it returns 503 with the service phase, cache provenance,
request counters, loaded domain sets, and data versions. Every HTTP response
includes X-Request-ID; server logs are structured JSON.

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
| Log level | --log-level | ADVERSARYFLOW_LOG_LEVEL | info |
| Download limit | — | ADVERSARYFLOW_MAX_BUNDLE_BYTES | 128 MiB |

## Network boundary

Loopback is the supported default. A non-loopback bind is refused unless
--allow-remote is present and a non-empty bearer token is supplied with
--api-token or ADVERSARYFLOW_API_TOKEN. The browser prompts once and holds the
token in session storage; every API route requires it. Use TLS at an
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
platform. Outcomes, timestamps, operator/target context, notes, and cleanup
verification are stored locally. Export a JSON plan for backup or handoff;
the welcome screen can resume a schema 2.0 JSON plan. Imported commands are
always elevated to high risk and require acknowledgment before copying.

Do not put secrets in execution notes or exports.

## Diagnostics

Run **adversaryflow doctor** to verify the Python/runtime versions, frontend
assets, cache visibility, and cache write access. For a support request attach:

1. adversaryflow --version;
2. redacted adversaryflow doctor output;
3. the X-Request-ID for a failing request;
4. operating system and browser versions;
5. the affected ATT&CK domain and data version.

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
