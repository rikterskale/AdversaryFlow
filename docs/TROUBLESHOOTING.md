# Guided troubleshooting

## Start here

1. **Preserve your work.** If the planner is open, choose **Finish & export →
   Save JSON plan** and check that the file reached Downloads.
2. **Use the right folder.** Open a command window in the extracted folder
   containing `docker-compose.yml` and `run.ps1`, as shown in the
   [README](../README.md#3-open-a-command-window-in-that-folder).
3. **Match your installation.** Docker commands below are for Docker installs;
   Python launcher commands are for native installs. Use the printed browser
   URL and leave the running service's window open.
4. **Try the specific fix.** Read the error in the command window or open the
   app's header status button for **System health → Host self-test**. Fix the
   first failing required check, then retry. Browser cleanup and Docker resets
   can lose saved records; they are not general setup fixes.

## Use another port

A port is the number at the end of the browser address. If another program
already uses `5000`, save your JSON backup and stop this startup with **Ctrl+C**.
Use the matching block in the application folder:

**Docker, Windows PowerShell:**

```powershell
$env:ADVERSARYFLOW_PORT = "5050"
docker compose up
```

**Docker, Mac or Linux:**

```bash
ADVERSARYFLOW_PORT=5050 docker compose up
```

**Python, Windows PowerShell:**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1 --port 5050
```

**Python, Mac or Linux:**

```bash
./run.sh --port 5050
```

Open **http://127.0.0.1:5050** and, for Docker, use the new startup token.
Browser autosave belongs to its original address: if progress looks empty,
restore your JSON file with **Resume JSON plan**. Reuse the same port when
restarting. To return a Windows Docker session to its default, stop it, run
`Remove-Item Env:ADVERSARYFLOW_PORT`, then `docker compose up`.

## Downloads or preparation fail

Check your internet connection and read the exact error. First-time setup
needs downloads; offline mode cannot replace an empty installation/cache.
On a managed network, give your IT team this list:

| Download | Hosts used by the default installation |
| --- | --- |
| Project ZIP | `github.com`, `codeload.github.com` |
| Python dependencies | `pypi.org`, `files.pythonhosted.org` |
| Official ATT&CK data | `raw.githubusercontent.com` |
| Docker base images | Docker Hub endpoints including `auth.docker.io` and `registry-1.docker.io`; Docker's image-download hosts may vary |
| Frontend dependencies during a Docker image build | `registry.npmjs.org` |

Ask IT to configure your organization's proxy and trusted certificates for
the affected tool. Do not disable HTTPS certificate checking as a workaround.
On Mac with Python.org's installer, run **Applications → Python 3.14 →
Install Certificates.command** and retry. If data preparation is still making
progress, wait; a slow first download is not by itself a failure.

## Native launcher problems

| Error or symptom | Next step |
| --- | --- |
| Python is missing, too old, or opens a Store download instead | Follow the [Python setup steps](GETTING_STARTED.md#1-install-python), reopen the command window, and check the version again. |
| `run.ps1` cannot be found | Open PowerShell in the extracted folder containing that file. Do not open the ZIP as if it were an installed application. |
| Windows says running scripts is disabled | Use `powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1` from the project folder, as documented in [Getting started](GETTING_STARTED.md#3-install-and-start). This is a process-only setting. If organization policy blocks it, ask IT to approve the installation. |
| `Permission denied` for `run.sh` or `install.sh` | In the application folder, run `chmod +x run.sh install.sh`, then `./run.sh`. |
| Python reports `No module named venv` or `ensurepip` is unavailable | On Ubuntu/Debian, install `python3-venv` and `python3-pip` using the native guide; for another distribution, use its package instructions. |
| `adversaryflow` is not recognized | Use the full path below from the application folder; no global command or environment activation is required. |
| The browser does not open automatically | Leave the service running and type its printed URL into your browser. |

## Run the self-test

For a **running Docker container**, open another command window in the
application folder:

```text
docker compose exec adversaryflow adversaryflow doctor
```

If the container cannot start, use `docker compose logs adversaryflow` instead.
For **Python on Windows**, stop the service first, then run:

```powershell
.\.venv\Scripts\adversaryflow.exe doctor
```

For **Python on Mac or Linux**, stop the service first, then run:

```bash
.venv/bin/adversaryflow doctor
```

Success is `"ok": true` and `"required_failed": 0`. A `FAIL` marked
`"required": false` is advisory. For example, Python users do not need Docker.
Run native command-line checks while the native service is stopped, or use
the in-app self-test, so its own running service does not occupy the tested port.

## Detailed diagnostic reference

Start with the same self-test the GUI uses:

```bash
adversaryflow doctor
```

The command returns structured JSON. Every check has a `PASS` or `FAIL`, a
plain-language detail, and a concrete `fix`. `required: true` checks determine
the command exit status. Docker and live-feed reachability are advisory because
AdversaryFlow also supports native, pipx, and intentionally offline operation.

In the GUI, open the status chip in the top-right corner to see the same report
under **Host self-test**. After applying a fix, select **Run self-test again**
and confirm the updated check time and status before retrying setup. No
diagnostic contacts a target system. The only external probe is an HTTPS
`HEAD` request to the configured official MITRE ATT&CK STIX source.

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
| Local service returns HTTP 403 about the request host | Local mode was opened through a custom hostname | Use the printed localhost/loopback URL. A remote deployment requires explicit remote mode and its bearer token. |
| Mutation returns HTTP 403 | The same-origin request token is absent or the browser origin differs | Use the GUI, or fetch `/api/session` and send `X-AdversaryFlow-CSRF` from the same origin. |
| Browser progress cannot be saved | Local storage is blocked, private, or full | Export schema-versioned JSON immediately, then restore it with **Resume JSON plan** in a storage-enabled profile. |
| Interface recovery repeats after reload | The saved browser workspace may be corrupt | Select **Download recovery copy**, confirm the file is saved, then **Reset browser workspace**. The recovery file preserves raw browser data for diagnosis; server-saved engagements are retained. |
| Execution-kit download fails | The live catalog changed, the request is too large, or the service rejected the plan | Keep the plan open, inspect the error toast and health panel, refresh only if necessary, then retry the download. The service rebinds commands to its catalog. |
| Report preview shows **Report generation failed** | The plan is invalid, the request exceeded 5 MiB, or the catalog could not rebind a technique | Keep the plan open, inspect the inline message and **System health**, then choose **Retry report generation**. Reports do not execute or include commands. |
| PDF or JSON download fails after the preview is ready | The service/session became unavailable after HTML generation | Keep the preview open, inspect the inline error and toast, restore the service or token, then retry that download. |

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

## Ask for help

Open a [GitHub bug report](https://github.com/rikterskale/AdversaryFlow/issues/new/choose)
and include:

- Windows/macOS/Linux and its version, plus your browser's name.
- Whether you used Docker or Python, and the step that failed.
- The exact error text and what you tried next.
- The version shown in the app or startup window, and the self-test output
  if you could run it. If not, say where startup stopped.

Before sharing logs or screenshots, remove **API tokens, passwords, private
notes, target names, and sensitive paths**. A screenshot is useful only after
those details are removed. Report suspected security vulnerabilities privately
using [Security](../SECURITY.md), not in a public issue.
