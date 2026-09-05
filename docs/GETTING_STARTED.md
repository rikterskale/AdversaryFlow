# Getting started

A copy/paste-safe operator handbook for **AdversaryFlow 0.4.0**.
Every `adversaryflow` / `adversaryflow-telemetry` invocation, launcher
`--help` / `--version`, and HTTP check quoted below was executed against
this tree. Installer success lines are the literal strings from
`install.sh` / `install.ps1`. `cache-clear --yes` is documented from the
CLI and tests; it was not run here because it deletes the ATT&CK cache.

This is the first document to read if you are installing AdversaryFlow,
proving it works, using it every day, or recovering from a broken cache.
Deeper contracts live in [INSTALL.md](INSTALL.md), [OPERATIONS.md](OPERATIONS.md),
[EXPORTS.md](EXPORTS.md), [TELEMETRY.md](TELEMETRY.md), and
[USER_JOURNEY.md](USER_JOURNEY.md).

---

## What you are installing

AdversaryFlow is a **local planner**. You pick a MITRE ATT&CK group or
campaign; it builds a kill-chain plan and attaches a lab command to every
technique. The web service **does not execute catalog commands**. You copy a
command (or hand an operator an offline kit) and run it only on a lab host
you are authorized to test.

It is **not** published on PyPI. `pipx install adversaryflow` is not an
install path today.

## Safety (read before any command)

- Use it only in a disposable lab you own or are explicitly authorized to
  test. See [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md).
- Leave **Allow high-risk commands**, **Allow administrator commands**, and
  **Allow network-active commands** off until you understand the card in
  front of you.
- A green **Ran** result means you ran the lab command. It is not proof that
  a detection fired. Record detection separately (Alerted / Silent / Blocked
  / Not instrumented).
- Bounded-exercise JSON receipts are self-reported. Correlate them with
  endpoint or SIEM telemetry before treating execution as independently
  proven.

## How to copy from this guide

- Copy **one entire fenced block**. Do not copy the `$` you might see in
  other docs; these blocks have none.
- Blocks labelled **Linux and macOS** are for `bash`. Blocks labelled
  **Windows** are for PowerShell.
- After a source checkout, `./run.sh` and `.venv/bin/adversaryflow` are the
  same program. The examples below use the venv command so they work in any
  shell that has already run `./install.sh`.

---

## 1. Check the machine

You need **Git** and **Python 3.10 or newer**.

Linux and macOS:

```bash
python3 --version
git --version
```

Windows PowerShell:

```powershell
py -3 --version
git --version
```

You should see a Python version of `3.10` or higher. This handbook was
checked with `Python 3.14.4`. If `python3` / `py -3` is missing, install
Python 3.10+ from your OS package manager or python.org, then retry. The
installer refuses older interpreters with:

```text
AdversaryFlow requires Python 3.10 or newer.
```

or, on Windows:

```text
AdversaryFlow requires Python 3.10 or newer. Install Python, then retry.
```

---

## 2. Install

AdversaryFlow is **not on PyPI**. Install from a Git checkout.

### 2.1 Clone (skip if you already have the tree)

```bash
git clone https://github.com/rikterskale/AdversaryFlow.git
cd AdversaryFlow
```

Windows PowerShell uses the same two lines.

### 2.2 Create the environment

Linux and macOS:

```bash
./install.sh
```

Windows PowerShell:

```powershell
.\install.ps1
```

That script checks Python ≥ 3.10, creates `.venv`, installs the hash-pinned
runtime and build sets, installs this package editable, and runs
`adversaryflow doctor`.

**Success looks like** the doctor JSON with `"ok": true`, then:

Linux and macOS:

```text
AdversaryFlow installed and verified. Start it with ./run.sh
```

Windows:

```text
AdversaryFlow installed and verified. Start it with .\run.ps1
```

### 2.3 Prove the CLI

Linux and macOS:

```bash
.venv/bin/adversaryflow --version
.venv/bin/adversaryflow doctor
```

Windows PowerShell:

```powershell
.\.venv\Scripts\adversaryflow.exe --version
.\.venv\Scripts\adversaryflow.exe doctor
```

`--version` must print exactly:

```text
AdversaryFlow 0.4.0
```

`doctor` must exit `0` and include:

```json
"ok": true,
"frontend_available": true,
"cache_writable": true,
"version": "0.4.0"
```

plus `"Flask"` and `"waitress"` versions under `"dependencies"`. If `"ok"`
is `false`, do not start the service; jump to [Issue remediation](#5-issue-remediation).

`install.sh` / `install.ps1` already ran `doctor` for you. Running it again
is the verification step, not a second install.

---

## 3. First verified proof of concept

This PoC proves **the planner works**. It does not emulate APT29 against a
network. You will:

1. start the local service;
2. confirm liveness and ATT&CK readiness over HTTP;
3. build an APT29 plan in the wizard;
4. export schema 2.0 JSON.

An optional, low-risk lab one-liner is at the end of this section. Skip it
if you are not on an authorized lab host.

Keep the terminal that starts AdversaryFlow open. Stopping that process
stops the service.

### 3.1 Start

Linux and macOS:

```bash
./run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

You should see, in order:

```text
[AdversaryFlow] starting; the browser will open when ATT&CK data is ready
AdversaryFlow 0.4.0: http://127.0.0.1:5000
```

Leave this terminal running. On a **first** enterprise start the UI shows
**Preparing MITRE ATT&CK data…** while it downloads and validates about
**54 MB** of STIX (`53835637` bytes in the cache this handbook was checked
against). Later starts reuse `~/.cache/adversaryflow` (Linux),
`~/Library/Caches/AdversaryFlow` (macOS), or
`%LOCALAPPDATA%\AdversaryFlow\Cache` (Windows).

If the browser does not open, go to <http://127.0.0.1:5000> yourself. The
page title is `AdversaryFlow — Adversary Emulation Planner`.

### 3.2 Prove the process is live

In a **second** terminal, from any directory:

Linux and macOS:

```bash
curl -sS http://127.0.0.1:5000/api/live
```

Windows PowerShell (use `curl.exe`, not the `curl` alias):

```powershell
curl.exe -sS http://127.0.0.1:5000/api/live
```

You should get HTTP 200 and:

```json
{"status":"live","version":"0.4.0"}
```

`/api/live` means the process can answer. It does **not** mean ATT&CK data
is ready.

### 3.3 Prove ATT&CK data is ready

```bash
curl -sS -w '\nHTTP %{http_code}\n' http://127.0.0.1:5000/api/health
```

Windows:

```powershell
curl.exe -sS -w "`nHTTP %{http_code}`n" http://127.0.0.1:5000/api/health
```

**Ready** is HTTP **200** and includes `"status": "ready"`, `"ready": true`,
`"phase": "ready"`, `"error": null`.

**Not ready yet** is HTTP **503** with `"status": "degraded"`. During a cold
start that is normal; wait and retry. The UI polls this for you.

If you started with `--no-preload` (this PoC does not), health stays
degraded with `"error": "ATT&CK data has not been loaded"` and
`"phase": "not_started"` until the UI (or a CSRF-protected
`POST /api/bootstrap`) loads the bundle.

### 3.4 Prove actors loaded

```bash
curl -sS http://127.0.0.1:5000/api/actors | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['actors']), d['data_version']); print(next(a for a in d['actors'] if a['attack_id']=='G0016')['name'])"
```

Windows PowerShell:

```powershell
curl.exe -sS http://127.0.0.1:5000/api/actors | py -3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['actors']), d['data_version']); print(next(a for a in d['actors'] if a['attack_id']=='G0016')['name'])"
```

Against the enterprise bundle this handbook used, that prints:

```text
227 enterprise:bundle--6198013c-6f02-42a4-9713-38ea1301a1aa
APT29
```

Your `data_version` string will change when MITRE publishes a new STIX
bundle. The actor count and `APT29` line are the check. The header chip in
the UI should read `227 actors · Enterprise` (or `1 actor` when only one
row is loaded).

### 3.5 Build an APT29 plan in the wizard

In the browser at <http://127.0.0.1:5000>:

1. Click **Start with APT29** (or **Begin emulation plan**, then search
   `APT29` / `G0016` and select it). The footer should read
   `Selected: APT29`. Click **Continue** if you used the gallery.
3. On **Scope the engagement**:
   - Set **Command platform** to the OS of the lab host you will type on
     (**Linux**, **Windows**, or **macOS**). There is no cross-OS fallback:
     a Windows-only command is unsupported on Linux, and copy is disabled.
   - Leave **Allow network-active commands**, **Allow administrator
     commands**, and **Allow high-risk commands** **off**.
   - Optional: fill **Operator** and **Target** (lab names only; no
     secrets).
4. Confirm the preview is non-zero runnable, then click **Build plan**.

Against the checked bundle, APT29 is **66** techniques across **13**
stages, all curated (`fallback_commands` is `0`). The plan opens on
**Reconnaissance**. Use **Next stage** until **Execution**.

You now have a verified planner PoC if the Execution stage shows lab
commands. Continue to export even if you do not run anything.

### 3.6 Optional: one low-risk lab command

Only on an authorized disposable lab. AdversaryFlow still does not execute
this; you do.

Stay on the **Execution** stage with high-risk / admin / network **off**.

| Lab OS | Technique to open | Fidelity you should see | Command the card shows |
| --- | --- | --- | --- |
| Linux | **T1059.006** Python | lab proxy | `python3 -c "print('AdversaryFlow lab python exec test')"` |
| Windows | **T1059.001** PowerShell | lab proxy | `powershell.exe -NoProfile -Command "Write-Host 'AdversaryFlow lab PowerShell exec test'"` |

1. Click **Copy command** on that card (no acknowledgement dialog; these
   are low risk).
2. Paste into a terminal **on the lab host**, not into a production jump
   box.
3. You should see `AdversaryFlow lab python exec test` or
   `AdversaryFlow lab PowerShell exec test`.
4. On the card, set **Command** to **Ran**, set **Detection** to whatever
   your lab actually did (**Not assessed** is honest if you did not look),
   and optionally tick **cleanup verified** if the card has cleanup.

Do not paste a command from a **bounded synthetic** card into this first
PoC. Those need Python 3.10+ and `python -m backend.lab_exercises <id>`
(Windows) or `python3 -m backend.lab_exercises <id>` (Linux). Direct
`T1059.006` is **not** a `lab_exercises` id; that module will reject it
with `invalid choice`.

### 3.7 Export JSON and check it

1. Click **Finish & export**. The footer reads `Plan complete`.
2. Click **JSON**. The file name is
   `AdversaryFlow_G0016_APT29.json`.
3. In the folder where the browser saved it:

```bash
python3 -c "import json; p=json.load(open('AdversaryFlow_G0016_APT29.json')); print(p['schema_version'], p['tool'], p['actor']['attack_id'], p['actor']['name'], p['summary']['techniques'], p['summary']['runnable'])"
```

Windows PowerShell:

```powershell
py -3 -c "import json; p=json.load(open('AdversaryFlow_G0016_APT29.json')); print(p['schema_version'], p['tool'], p['actor']['attack_id'], p['actor']['name'], p['summary']['techniques'], p['summary']['runnable'])"
```

You should see `2.0 AdversaryFlow G0016 APT29` followed by technique counts
(66 and a runnable count that depends on the platform you picked). Keep this
file. It is the portable backup of the plan.

### PoC success checklist

- [ ] `adversaryflow --version` prints `AdversaryFlow 0.4.0`
- [ ] `adversaryflow doctor` has `"ok": true`
- [ ] `GET /api/live` returns `"status":"live"`
- [ ] `GET /api/health` returns HTTP 200 `"ready": true`
- [ ] `GET /api/actors` lists **APT29** / **G0016**
- [ ] The wizard built an APT29 plan and exported schema **2.0** JSON

That is a verified PoC of the product you installed. It is not a detection
coverage claim.

Stop the service with **Ctrl+C** in the terminal that is running `./run.sh`
(or `.\run.ps1`).

---

## 4. Everyday use

### Start and stop

Same as the PoC: `./run.sh` or `.\run.ps1`, then Ctrl+C to stop.

Pass-through flags go to `adversaryflow`. Useful ones, all verified on
`--help`:

```bash
./run.sh --port 5050
./run.sh --offline
./run.sh --cache-dir /path/to/cache
```

Windows: `.\run.ps1 --port 5050`

Default bind is `127.0.0.1:5000`. A non-loopback host is refused unless you
pass **both** `--allow-remote` and `--api-token` (or
`ADVERSARYFLOW_API_TOKEN`). Loopback is the supported mode; see
[OPERATIONS.md](OPERATIONS.md) before changing it.

### Resume work

- **Same browser, same machine:** the welcome screen offers
  **Resume &lt;actor&gt; plan** after a reload. Evidence lives in this
  browser's local storage, keyed by actor, ATT&CK data version, domains, and
  command platform.
- **Another machine or browser:** **Resume JSON plan** and choose a schema
  2.0 export. Imported commands are re-classified as high risk and need
  acknowledgement before copy.

Export JSON when a session matters. The save chip on the plan screen reads
**Saved in this browser** (or **Not saved in this browser** if storage
throws).

### Scope, plan, keyboard

- Platform is exact. Switching Windows → Linux does not substitute a
  Windows command.
- **Command** (Not run / Ran / Failed / Skipped) is independent of
  **Detection** (Not assessed / Alerted / Silent / Blocked / Not
  instrumented).
- On the plan screen, `j` / `k` move the focused card and `c` copies its
  lab command. Evidence edits do not rebuild the stage, so notes and an
  open proof panel stay put.
- High-risk copy opens an in-app dialog that shows the command. Cancel is
  always allowed.

### Refresh ATT&CK

In the header, **↻ Refresh the live ATT&CK feed** (needs the same-origin
token the UI already holds). From the CLI, after the service is **stopped**:

```bash
.venv/bin/adversaryflow cache-refresh --domains enterprise
```

`--domains` is a comma-separated list from `enterprise`, `ics`, `mobile`.
An unknown name exits `2` with:

```text
Unknown ATT&CK domain(s): bogus
```

Do not refresh from two terminals at once while the UI is also refreshing;
the API returns HTTP 409 `refresh_in_progress` or 429
`refresh_rate_limited` (five-second cooldown).

### Exports

On **Finish & export**:

| Control | What you get |
| --- | --- |
| **Download operator execution kit** | ZIP: catalog-rebound CSV + PowerShell (Windows) or Bash (Linux/macOS) runner. Bounded synthetic steps add `AdversaryFlow-exercises.py` (needs Python 3.10+ beside the kit). Direct steps need no AdversaryFlow install on the destination. |
| **Markdown report** | Human-readable plan, including **Outcome** and **Detection**. |
| **JSON** | Schema 2.0; this is the file you resume later. |
| **Runbook** | `.txt` with every command commented (`REM` / `#`). It is not a script. |

The service never runs kit commands. The destination runner asks run / edit
/ skip / abort per step.

### Offline

Seed the cache while online (a normal first start does this for
enterprise), then:

```bash
.venv/bin/adversaryflow cache-status
./run.sh --offline
```

`cache-status` prints JSON with `cache_dir`, `offline`, and per-domain
`exists` / `fresh` / `sha256`. Offline mode never downloads. A missing
enterprise bundle fails bootstrap with:

```text
offline mode requires a cached enterprise ATT&CK bundle at <cache>/enterprise-attack.json
```

### Independent telemetry (after a bounded exercise)

This is not part of the first PoC. After a current `./install.sh`, the
console script is `adversaryflow-telemetry`:

```bash
.venv/bin/adversaryflow-telemetry --help
.venv/bin/adversaryflow-telemetry criteria T1110
```

`criteria T1110` returns the pass gate for that bounded exercise (T1110
requires five `authentication_failure` events plus a run-id marker). See
[TELEMETRY.md](TELEMETRY.md) for `collect` and `correlate`. A source
checkout can also run `.venv/bin/python -m backend.telemetry` with the same
subcommands.

---

## 5. Issue remediation

Match what you see, then run the command in the **Fix** column. Quoted
strings are exact CLI or HTTP output.

| You see | Likely cause | Fix |
| --- | --- | --- |
| `AdversaryFlow requires Python 3.10 or newer.` | Interpreter too old or missing | Install Python 3.10+, confirm with `python3 --version` / `py -3 --version`, rerun `./install.sh` |
| `doctor` has `"ok": false` and `"frontend_available": false` | Frontend files not next to the package | Run install from a full git checkout; or set `ADVERSARYFLOW_FRONTEND_DIR` to the `frontend/` directory |
| `doctor` has `"cache_writable": false` | Cache directory not writable | `adversaryflow --cache-dir /path/you/own doctor` then start with the same `--cache-dir` |
| Browser never opens, nothing listens | Start failed, or you closed the terminal | Run `./run.sh` again; confirm `AdversaryFlow 0.4.0: http://127.0.0.1:5000` |
| `OSError: [Errno 98] Address already in use` (Windows: WinError 10048) | Port 5000 taken | `./run.sh --port 5050` and open <http://127.0.0.1:5050> |
| `/api/live` works, `/api/health` is HTTP 503 `"degraded"` | ATT&CK still loading, or load failed | If the UI still says **Preparing MITRE ATT&CK data…**, wait. If `"phase": "failed"`, read `"error"` and the next rows |
| `"error": "ATT&CK data has not been loaded"` | Started with `--no-preload` and bootstrap never ran | Start **without** `--no-preload`, or click **Retry setup** in the UI |
| `offline mode requires a cached enterprise ATT&CK bundle at …` | `--offline` with an empty cache | Start **online** once, or copy a known-good cache into `--cache-dir` |
| Header chip `setup needs attention` / `Could not prepare ATT&CK data` | Session or bootstrap failed | Click **Retry setup**. Confirm `GET /api/session` returns `csrf_token` and `version` |
| `{"error":"forbidden","message":"Missing or invalid same-origin request token"}` | `POST` without `X-AdversaryFlow-CSRF` | Use the UI, or `GET /api/session` and send that token. Ordinary `GET /api/live` and `GET /api/health` do not need it |
| `{"error":"actor_not_found",…}` | Wrong STIX id or domain | Search the gallery; APT29 is `G0016` / `intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542` on enterprise |
| `{"error":"bad_request","message":"Unknown ATT&CK domain(s): bogus"}` | Typo in `?domains=` | Use `enterprise`, `ics`, `mobile` only |
| Card says **unsupported** / copy disabled | Platform mismatch or scope filter | Switch **Command platform**, or enable the matching Allow-* toggle. Do not expect a Windows command on Linux |
| In-app dialog **Copy this high risk lab command?** | Medium/high-risk copy | Read the command, prerequisites, and cleanup. Cancel if this is not your lab |
| Toast **Progress can't be saved in this browser** | `localStorage` threw | Export JSON immediately. Private mode and full disks commonly cause this |
| `Refusing to clear the cache without --yes.` (exit 2) | `cache-clear` without confirmation | Intended. Add `--yes` only when you mean to delete the bundle |
| `Refusing a non-loopback bind without --allow-remote.` (exit 2) | `--host 0.0.0.0` | Stay on 127.0.0.1, or read OPERATIONS.md before opting in |
| `Refusing a non-loopback bind without --api-token or ADVERSARYFLOW_API_TOKEN.` (exit 2) | Remote bind, no token | Supply `--api-token` as well as `--allow-remote` |
| `adversaryflow: error: argument command: invalid choice: 'nosuch'` (exit 2) | Typo | Commands are only `serve`, `doctor`, `cache-status`, `cache-refresh`, `cache-clear` |
| `pipx install adversaryflow` cannot find a package | Not on PyPI | Use `./install.sh` or a GitHub Release wheel. See [Upgrades](#7-upgrades) |

Show the CLI list any time:

```bash
.venv/bin/adversaryflow --help
```

---

## 6. Recovery

Work top-down. Do **not** start with `cache-clear`.

### 6.1 Save the plan

If the UI still opens, **Finish & export → JSON**. That file restores
outcomes and notes via **Resume JSON plan**.

### 6.2 Confirm the process vs the data

```bash
curl -sS http://127.0.0.1:5000/api/live
curl -sS http://127.0.0.1:5000/api/health
.venv/bin/adversaryflow doctor
.venv/bin/adversaryflow cache-status
```

| live | health | Meaning |
| --- | --- | --- |
| 200 `"live"` | 200 `"ready"` | Service is fine; look at the browser or the plan file |
| 200 `"live"` | 503 `"degraded"` | Process up, ATT&CK not ready — read `phase` and `error` |
| connection refused | | Process is not running — `./run.sh` |

### 6.3 Repair a bad cache

1. Copy `cache-status` JSON somewhere if you need provenance (`sha256`,
   `source_url`, `downloaded_at`).
2. Stop the service (Ctrl+C).
3. Only then:

```bash
.venv/bin/adversaryflow cache-clear --yes
```

That prints a JSON object with `"removed"` listing only AdversaryFlow
`*-attack.json` / `*-attack.meta.json` files. It will not empty an
unrelated folder.

4. Start **online** with `./run.sh` so enterprise can download again
   (~54 MB).

### 6.4 Reinstall the application

Stop the service, then from the checkout:

```bash
./install.sh
.venv/bin/adversaryflow --version
.venv/bin/adversaryflow doctor
```

Windows: `.\install.ps1` and `.\.venv\Scripts\adversaryflow.exe`.

`./run.sh` does **not** reinstall if `.venv/bin/adversaryflow` already
exists. After a `git pull`, run `./install.sh` yourself.

### 6.5 What is safe to delete

| Path | Role | Delete? |
| --- | --- | --- |
| Browser local storage | In-progress evidence | Lost on clear-site-data; export JSON first |
| Per-user ATT&CK cache | ~54 MB STIX + sidecar | Only via `cache-clear --yes` |
| `.venv/` | Installed CLI | Recreated by `./install.sh` |
| Exported JSON / kits | Your records | Back these up; AdversaryFlow does not |

---

## 7. Upgrades

AdversaryFlow **0.4.0** is the current package version
(`backend/__init__.py`, `adversaryflow --version`). It is **not** on PyPI.

### From a git checkout (supported)

```bash
cd AdversaryFlow
git pull
./install.sh
.venv/bin/adversaryflow --version
.venv/bin/adversaryflow doctor
```

Windows: `git pull`, then `.\install.ps1`.

Read [CHANGELOG.md](../CHANGELOG.md) before you reuse an old JSON plan.
Imported files must be schema **2.0**; a `1.0` export is refused with
`This is not an AdversaryFlow 2.0 plan export`.

### From a wheel

After you build a wheel or download a GitHub Release asset:

```bash
pipx install ./adversaryflow-0.4.0-py3-none-any.whl
adversaryflow --version
adversaryflow doctor
adversaryflow --open
```

Replace the filename with the wheel you actually have. Upgrade that install
later with `pipx upgrade adversaryflow` only if pipx originally installed
**this project's wheel or git URL**. `pipx install adversaryflow` (no path)
resolves on PyPI and will fail until a release is published there.

### After a version bump

1. Confirm `--version` matches the changelog heading you intended.
2. Confirm `doctor` `"ok": true`.
3. Confirm `/api/health` `"version"` matches.
4. Rebuild any in-progress plan if ATT&CK `data_version` changed; the UI
   warns on resume when the saved bundle id does not match.

---

## 8. Support escalation

Collect facts first. Do not paste secrets, tokens, home-directory dumps, or
weaponized commands into a public issue.

### Before you open an issue

Linux and macOS (service may be stopped for `doctor`):

```bash
.venv/bin/adversaryflow --version
.venv/bin/adversaryflow doctor
curl -sS http://127.0.0.1:5000/api/live
curl -sS http://127.0.0.1:5000/api/health
```

Copy:

1. The exact `--version` line.
2. Redacted `doctor` JSON (`ok`, `python`, `frontend_available`,
   `cache_writable`, `version`; you may strip `cache.path`).
3. Health `status`, `phase`, `error`, `version`, and `data_versions` (not
   filesystem paths if you need to keep those private).
4. The `X-Request-ID` header from a failing response
   (`curl -sS -D - http://127.0.0.1:5000/api/health | head`).
5. OS, Python version, browser, selected ATT&CK domains, and the steps to
   reproduce.

### Where to send it

| Kind | Where |
| --- | --- |
| Product does the wrong thing | GitHub **Bug report** template: https://github.com/rikterskale/AdversaryFlow/issues/new/choose |
| Feature request | GitHub **Feature request** template (same URL) |
| Suspected vulnerability | GitHub **private** vulnerability report only. Do not open a public issue. See [SECURITY.md](../SECURITY.md) |
| “How do I target a network I do not own?” | Do not file it. That use is outside [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md) |

Support is the **latest minor release** only ([SUPPORT.md](../SUPPORT.md)).
Maintainers acknowledge private vulnerability reports within five business
days.

---

## Command cheat sheet

Verified against `adversaryflow --help` on 0.4.0. Default command is
`serve`.

```text
adversaryflow --version
adversaryflow --help
adversaryflow doctor
adversaryflow cache-status
adversaryflow cache-refresh --domains enterprise
adversaryflow cache-refresh --domains enterprise,ics,mobile
adversaryflow cache-clear --yes
adversaryflow --open
adversaryflow --port 5050 --open
adversaryflow --offline --open
adversaryflow --cache-dir /path/to/cache --open
adversaryflow --no-preload
adversaryflow --log-level debug
```

HTTP checks (service running on the default port):

```text
GET  http://127.0.0.1:5000/
GET  http://127.0.0.1:5000/api/live
GET  http://127.0.0.1:5000/api/health
GET  http://127.0.0.1:5000/api/session
GET  http://127.0.0.1:5000/api/actors
GET  http://127.0.0.1:5000/api/bootstrap
```

Related CLIs (not required for the first PoC):

```text
adversaryflow-telemetry --help
adversaryflow-telemetry criteria T1110
python -m backend.lab_exercises --help
```
