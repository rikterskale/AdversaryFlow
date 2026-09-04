# Installation

AdversaryFlow supports Python 3.10 or newer on Linux, macOS, and Windows.

## One-command source install

Linux and macOS:

```bash
./run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

The first run creates `.venv`, installs the pinned runtime set, installs AdversaryFlow, and starts it. Later launches do not reinstall dependencies.

## Package install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
adversaryflow
```

On PowerShell, activate with `.\.venv\Scripts\Activate.ps1`.

## Runtime options

```text
adversaryflow [--host HOST] [--port PORT] [--cache-dir PATH]
              [--offline] [--no-preload] [--version]
```

Equivalent environment variables are `ADVERSARYFLOW_HOST`, `ADVERSARYFLOW_PORT`, `ADVERSARYFLOW_CACHE_DIR`, `ADVERSARYFLOW_OFFLINE`, and `ADVERSARYFLOW_FRONTEND_DIR`.

The default cache is outside the installation:

- Linux: `$XDG_CACHE_HOME/adversaryflow` or `~/.cache/adversaryflow`
- macOS: `~/Library/Caches/AdversaryFlow`
- Windows: `%LOCALAPPDATA%\AdversaryFlow\Cache`

## Offline use

After the required domain bundles have been cached, start with:

```bash
adversaryflow --offline
```

Offline mode never refreshes the feed. If a requested domain is not cached, readiness and API responses report the missing cache path.

## Upgrade and uninstall

Upgrade a source checkout deliberately:

```bash
git pull
./install.sh
```

Remove the source installation by deleting its `.venv`. A package installation can be removed with `python -m pip uninstall adversaryflow`.

