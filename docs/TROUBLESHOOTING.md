# Guided troubleshooting

Start with the same self-test the GUI uses:

```bash
adversaryflow doctor
```

The command returns structured JSON. Every check has a `PASS` or `FAIL`, a
plain-language detail, and a concrete `fix`. `required: true` checks determine
the command exit status. Docker and live-feed reachability are advisory because
AdversaryFlow also supports native, pipx, and intentionally offline operation.

In the GUI, open the status chip in the top-right corner to see the same report
under **Host self-test**. No diagnostic contacts a target system. The only
external probe is an HTTPS `HEAD` request to the configured official MITRE
ATT&CK STIX source.

## Symptom → cause → fix

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Python runtime` is `FAIL` | Python is older than 3.10 | Install Python 3.10 or newer, recreate the virtual environment, then rerun `adversaryflow doctor`. |
| `Docker and Compose` is `FAIL` | Docker is absent, inaccessible, or missing Compose v2 | For the one-command install, start Docker Desktop/Engine and install the Compose v2 plugin. Native and pipx installs may ignore this advisory failure. |
| `Frontend assets` is `FAIL` | The wheel/source checkout is incomplete or the frontend path is wrong | Reinstall from a complete release, or point `ADVERSARYFLOW_FRONTEND_DIR` at the built `frontend/` directory. |
| `Pinned runtime dependencies` is `FAIL` | Flask or Waitress is missing from the active environment | Reinstall using `python -m pip install --require-hashes -r requirements.lock`, or reinstall the wheel with pipx. |
| `Service port` is `FAIL` / `Address already in use` | Another process owns the configured port | Stop that process or start with `--port 5050` / `ADVERSARYFLOW_PORT=5050`. With Compose, set `ADVERSARYFLOW_PORT=5050`. |
| `Cache directory` is `FAIL` | The cache path is read-only or owned by another account | Choose a writable `--cache-dir`; for Compose, verify the `adversaryflow-stix-cache` volume can be written by UID/GID `10001`. |
| `STIX cache integrity` is `FAIL` | A bundle is truncated, malformed, or does not match its recorded SHA-256 | Stop the service, preserve provenance if needed, run `adversaryflow cache-clear --yes`, then restart online to download a verified bundle. |
| `Cache disk space` is `FAIL` | Less than 256 MiB is free on the cache filesystem | Free space or move `ADVERSARYFLOW_CACHE_DIR` / the Compose volume to a larger disk. |
| `ATT&CK feed reachability` is `FAIL` | Offline mode, DNS/proxy/TLS trouble, or blocked GitHub raw content | If online updates are required, allow HTTPS to `raw.githubusercontent.com` and correct proxy/DNS/TLS settings. Otherwise use `--offline` only with a validated cache. |
| `docker compose up` exits or restarts repeatedly | Docker is stopped, the host port is occupied, the cache volume is not writable, or the image build failed | Start Docker, run `docker compose ps` and `docker compose logs adversaryflow`, then follow the first reported failure. Use `ADVERSARYFLOW_PORT=5050` when port 5000 is occupied. |
| GUI status says `setup needs attention` | Session creation, bootstrap, or actor loading failed | Open **System health**, follow the first failing required check, then choose **Retry setup**. |
| `/api/live` is 200 but `/api/health` is 503 | The process is live but ATT&CK data is loading or failed | Read `phase` and `error` in `/api/health`; wait if loading, otherwise use the GUI self-test or `adversaryflow doctor`. |
| Both `/api/live` and the GUI are unreachable | The service did not start, exited, or is on another port | Run `docker compose ps` or restart the native launcher. Confirm the printed URL and the port check. |
| Refresh reports a conflict | Bootstrap or another refresh owns the refresh lock | Wait for the current operation to finish, then retry once. Refresh is intentionally serialized and rate-limited. |
| Remote API returns HTTP 401 | A non-loopback service requires the configured bearer token | Use the GUI token dialog and the same `ADVERSARYFLOW_API_TOKEN`; do not put tokens in URLs or logs. |
| Mutation returns HTTP 403 | The same-origin request token is absent or the browser origin differs | Use the GUI, or fetch `/api/session` and send `X-AdversaryFlow-CSRF` from the same origin. |
| Browser progress cannot be saved | Local storage is blocked, private, or full | Export schema-versioned JSON immediately, then restore it with **Resume JSON plan** in a storage-enabled profile. |
| Execution-kit download fails | The live catalog changed, the request is too large, or the service rejected the plan | Keep the plan open, inspect the error toast and health panel, refresh only if necessary, then retry the download. The service rebinds commands to its catalog. |
| HTML/PDF report download fails | The plan is incomplete, the request exceeded 5 MiB, or the catalog could not rebind a technique | Keep the plan open, inspect the error toast and **System health**, export JSON as a backup, then retry. Reports do not execute or include commands. |

## Safe recovery order

1. Export the current plan as JSON if the GUI is still available.
2. Capture `adversaryflow doctor` and `adversaryflow cache-status` output.
3. Correct the first failing required check and rerun `doctor`.
4. Restart the service and confirm `/api/live`, then `/api/health`.
5. Clear the STIX cache only when the integrity check fails or support directs
   you to. `cache-clear --yes` is destructive and removes only known
   AdversaryFlow bundle and metadata files.

For support, redact local paths if needed and include the AdversaryFlow version,
the diagnostics report, the failing request's `X-Request-ID`, operating system,
browser, ATT&CK domain, and data version.
