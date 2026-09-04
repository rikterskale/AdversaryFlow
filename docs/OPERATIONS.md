# Operations

## Health and readiness

`GET /api/health` returns HTTP 200 only after at least one ATT&CK index has loaded successfully. Before that it returns HTTP 503 with `status: degraded`, a human-readable error, loaded domain sets, and data versions.

## Configuration

| Setting | CLI | Environment | Default |
| --- | --- | --- | --- |
| Bind address | `--host` | `ADVERSARYFLOW_HOST` | `127.0.0.1` |
| Port | `--port` | `ADVERSARYFLOW_PORT` | `5000` |
| Cache directory | `--cache-dir` | `ADVERSARYFLOW_CACHE_DIR` | Per-user cache |
| Offline mode | `--offline` | `ADVERSARYFLOW_OFFLINE=1` | Disabled |
| Skip startup load | `--no-preload` | — | Disabled |

## Data lifecycle

The first enterprise load currently downloads approximately 54 MB. Bundles are cached for seven days. Enterprise, ICS, mobile, and combined domain indexes are isolated and report their bundle IDs as `data_version` metadata.

If startup loading fails, the service remains available in degraded mode so the UI and health endpoint can explain the failure. A successful actor, workflow, or refresh request restores readiness.

## Logs and troubleshooting

- `503 /api/health`: ATT&CK data has not loaded; inspect `error` and verify the cache/network state.
- `offline mode requires a cached ... bundle`: seed that domain while online or point `--cache-dir` to an existing cache.
- Port already in use: select another port, for example `adversaryflow --port 5050`.
- UI reports an unreadable response: check the launcher output for the structured backend exception.

