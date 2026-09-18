# Installation

AdversaryFlow supports Docker Compose as the zero-dependency application path,
plus Python 3.10 or newer on Linux, macOS, and Windows for native installs.
All paths keep the planner local by default and never execute attack commands.

If you are installing for the first time, use the copy/paste handbook
[Getting started](GETTING_STARTED.md) instead of this page. This file is
the compact reference for the same commands.

## One-command Docker Compose install

From the repository root:

~~~bash
docker compose up
~~~

Compose builds the hash-locked application image, creates the persistent
`adversaryflow-stix-cache` volume, and publishes the web UI only on
`127.0.0.1:5000`. The startup banner prints the URL, a cryptographically random
per-start API token, and the next step. Open the URL and enter that token when
prompted. The initial ATT&CK Enterprise download is approximately 54 MB; the
container reports healthy only after `/api/health` is ready.

Stop with Ctrl+C. Run `docker compose up` again to restart; the cache volume is
reused. To run in the background, use `docker compose up --detach`, then read
the URL and token with `docker compose logs adversaryflow`.

Optional settings are environment variables, not source edits:

~~~bash
# Linux/macOS: choose another loopback host port
ADVERSARYFLOW_PORT=5050 docker compose up

# Supply a stable token instead of the generated per-start token
ADVERSARYFLOW_API_TOKEN='replace-with-a-long-random-value' docker compose up
~~~

PowerShell:

~~~powershell
$env:ADVERSARYFLOW_PORT = "5050"
docker compose up
~~~

Compose passes the supported launcher settings through with these safe
defaults:

| Setting | Compose environment variable | Default | Notes |
| --- | --- | --- | --- |
| Host publication | `ADVERSARYFLOW_BIND_ADDRESS` | `127.0.0.1` | Host-side safety boundary; change only for deliberate remote access |
| Service bind | `ADVERSARYFLOW_HOST` | `0.0.0.0` | Container-internal bridge bind; the host publication remains loopback-only |
| Host and container port | `ADVERSARYFLOW_PORT` | `5000` | Changes both sides of the port mapping and the readiness probe |
| STIX cache directory | `ADVERSARYFLOW_CACHE_DIR` | `/var/lib/adversaryflow/cache` | Target of the persistent named volume |
| Offline mode | `ADVERSARYFLOW_OFFLINE` | `false` | Set `true` only after the named volume contains a validated bundle |
| API token | `ADVERSARYFLOW_API_TOKEN` | Generated per start | A supplied token is required for remote publication |
| Log level | `ADVERSARYFLOW_LOG_LEVEL` | `info` | One of `debug`, `info`, `warning`, or `error` |
| Printed URL | `ADVERSARYFLOW_PUBLIC_URL` | Loopback URL using the selected port | Set to the TLS proxy URL for remote access |

The port remains loopback-only even when changed. Bridge networking requires
the service to listen on its container interface, so the existing
`--allow-remote` and bearer-token application gate remain active inside the
container. Container hardening also includes a non-root user, a read-only root
filesystem, dropped Linux capabilities, and `no-new-privileges`.

Remote publication is deliberately off by default. If an authorized lab has a
TLS-protected reverse proxy and host firewall rules, opt in explicitly:

~~~bash
ADVERSARYFLOW_BIND_ADDRESS=0.0.0.0 \
ADVERSARYFLOW_API_TOKEN='<long-random-token-from-your-secret-manager>' \
ADVERSARYFLOW_PUBLIC_URL='https://adversaryflow.lab.example' \
docker compose up
~~~

The entrypoint refuses a non-loopback `ADVERSARYFLOW_BIND_ADDRESS` when
`ADVERSARYFLOW_API_TOKEN` is empty. Never commit a token to the Compose file or
an `.env` file, and never expose the plain HTTP service directly to the
internet.

Run the same preflight inside a running container with:

~~~bash
docker compose exec adversaryflow adversaryflow doctor
~~~

It recognizes the container context and the service's own occupied port. Run
`docker version` and `docker compose version` on the host when the stack itself
cannot start.

## Docker troubleshooting matrix

Start with `docker compose logs adversaryflow` when a container was created,
then match the first failure below. These fixes preserve the named cache volume
unless the cache-integrity row explicitly tells you to clear it.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `docker: command not found`, `docker is not recognized`, or `docker compose version` fails | Docker or the Compose v2 plugin is not installed | Install Docker Engine or Docker Desktop with Compose v2, open a new terminal, and confirm `docker version` plus `docker compose version`. |
| `Cannot connect to the Docker daemon` or Docker Desktop reports that the engine is stopped | Docker is installed but its engine is not running | Start Docker Engine/Desktop, wait until it reports ready, then rerun `docker compose up`. |
| `port is already allocated`, `address already in use`, or WinError 10048 | Another process owns port 5000 | Start with `ADVERSARYFLOW_PORT=5050 docker compose up` (PowerShell: `$env:ADVERSARYFLOW_PORT = "5050"` first), then open the printed URL. |
| Setup remains on ATT&CK preparation or `/api/health` reports a download error | DNS, proxy, TLS inspection, or firewall policy blocks the official feed | Allow HTTPS to `raw.githubusercontent.com`, correct the host/Docker proxy and CA settings, then restart. Use `ADVERSARYFLOW_OFFLINE=true` only after a validated cache has been seeded. |
| `STIX cache integrity` is `FAIL`, or logs report malformed data or a SHA-256 mismatch | The named-volume bundle or metadata sidecar is stale, truncated, or corrupt | Preserve provenance if needed, run `docker compose down`, then `docker compose run --rm adversaryflow cache-clear --yes`, and restart online with `docker compose up`. |
| `Cache disk space` is `FAIL`, `no space left on device`, or the download cannot be promoted | Docker's storage filesystem has less than 256 MiB free | Check `docker system df`, free at least 256 MiB without deleting required volumes, or move Docker's data storage to a larger disk; then rerun `docker compose up`. |

## One-command native source checkout

Linux and macOS:

~~~bash
./run.sh
~~~

Windows PowerShell:

~~~powershell
.\run.ps1
~~~

The native launcher verifies Python 3.10+, creates .venv, installs the pinned runtime
set, runs **adversaryflow doctor**, starts the service, and opens the browser
when ATT&CK data is ready. Later launches reuse the environment.

## Isolated install from a wheel

Download the `.whl` from the [GitHub Releases](https://github.com/rikterskale/AdversaryFlow/releases)
page, or build one with `python -m build`, then install that file:

~~~bash
pipx install ./adversaryflow-0.4.0-py3-none-any.whl
adversaryflow --open
~~~

You can also point pipx at this repository:

~~~bash
pipx install git+https://github.com/rikterskale/AdversaryFlow.git
~~~

Replace a local wheel with **pipx install --force ./adversaryflow-….whl**.
Upgrade a git-URL install with **pipx upgrade adversaryflow**. Remove either
with **pipx uninstall adversaryflow**. Do not run `pipx install adversaryflow`.

## Manual source setup

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes --requirement requirements.lock
python -m pip install --require-hashes --requirement requirements-build.lock
python -m pip install --no-build-isolation --no-deps --editable .
adversaryflow doctor
adversaryflow --open
~~~

On PowerShell, activate with .\.venv\Scripts\Activate.ps1.

## Runtime and maintenance commands

~~~text
adversaryflow [serve] [--host HOST] [--port PORT] [--cache-dir PATH]
                    [--offline] [--no-preload] [--open]
                    [--allow-remote] [--api-token TOKEN]
                    [--log-level LEVEL] [--version]
adversaryflow doctor
adversaryflow cache-status
adversaryflow cache-refresh [--domains enterprise,ics,mobile]
adversaryflow cache-clear --yes
~~~

Environment equivalents include ADVERSARYFLOW_HOST, ADVERSARYFLOW_PORT,
ADVERSARYFLOW_CACHE_DIR, ADVERSARYFLOW_OFFLINE, ADVERSARYFLOW_FRONTEND_DIR,
ADVERSARYFLOW_LOG_LEVEL, ADVERSARYFLOW_API_TOKEN, and
ADVERSARYFLOW_MAX_BUNDLE_BYTES.

The default cache is outside the installation:

- Linux: $XDG_CACHE_HOME/adversaryflow or ~/.cache/adversaryflow
- macOS: ~/Library/Caches/AdversaryFlow
- Windows: %LOCALAPPDATA%\AdversaryFlow\Cache

## Offline use

Seed the required domains while online, inspect them with **adversaryflow
cache-status**, then start with:

~~~bash
adversaryflow --offline --open
~~~

Offline mode never refreshes. Missing or invalid data produces an actionable
cache error and leaves the UI available for retry and diagnostics.
