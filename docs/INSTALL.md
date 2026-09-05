# Installation

AdversaryFlow supports Python 3.10 or newer on Linux, macOS, and Windows.
The supported path is a source checkout or a GitHub Release wheel.

If you are installing for the first time, use the copy/paste handbook
[Getting started](GETTING_STARTED.md) instead of this page. This file is
the compact reference for the same commands.

## One-command source checkout

Linux and macOS:

~~~bash
./run.sh
~~~

Windows PowerShell:

~~~powershell
.\run.ps1
~~~

The launcher verifies Python 3.10+, creates .venv, installs the pinned runtime
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
