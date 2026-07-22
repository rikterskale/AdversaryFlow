# Installation guide

This guide covers a first installation, minimal runtime installation, isolated
CLI installation, wheel builds, offline deployment, Docker, upgrades, and
uninstallation. Commands are shown separately where Windows and Unix shells differ.

## Choose an installation method

| You are... | Recommended method | Result |
|---|---|---|
| New to Python or evaluating the project | Repository task runner | A project-local `.venv`, examples, development tools, and `.env` template |
| Using the CLI from a source checkout | Minimal virtual environment | Runtime dependencies without test/lint tools |
| Installing one isolated command-line application | `pipx` from the checkout or a built wheel | A globally available `adversaryflow` command in its own environment |
| Packaging for controlled deployment | Build and install a wheel | Reproducible installable artifact for the target environment |
| Avoiding a host Python installation | Docker | A non-root container image with a persistent `/work` volume |

AdversaryFlow is not documented here as a public package-index release. Commands
install from the repository checkout or from a wheel you build. Do not assume
`pip install adversaryflow` retrieves this project from a public index unless a
release process has explicitly published and verified it.

## Requirements

- Python 3.11 or newer for native installation.
- Internet access during the first install, unless an offline wheelhouse is prepared.
- Git only when cloning; a downloaded source archive works without Git.
- Docker Desktop or Docker Engine only for the container method.

Check Python before continuing:

**Windows PowerShell**

```powershell
py --version
python --version
```

Use whichever command reports Python 3.11 or newer. If both fail, install Python
from python.org or the Microsoft Store. With the python.org installer, enable
“Add python.exe to PATH.” If several versions are installed, explicitly use
`py -3.11`, `py -3.12`, or a newer compatible version.

**Linux / macOS**

```bash
python3 --version
```

If it is older than 3.11, install a newer interpreter through the operating
system package manager or python.org. On Debian/Ubuntu, the matching `python3-venv`
package may also be required. On macOS, a current Homebrew Python is suitable.

## Get the source

Clone the repository:

```bash
git clone https://github.com/rikterskale/adversaryflow.git
cd adversaryflow
```

Alternatively, extract a source archive and open a terminal in the directory
containing `pyproject.toml`, `tasks.py`, and `README.md`. All repository-relative
commands below must be run from that directory.

## Method A: guided repository setup

This is the recommended beginner path. It installs editable source plus test and
lint tools. The task runner always uses `.venv` after creating it, so activation
is optional.

### Windows

```powershell
py -3.11 tasks.py setup
py -3.11 tasks.py demo
```

If `py -3.11` is unavailable but `python --version` reports 3.11 or newer:

```powershell
python tasks.py setup
python tasks.py demo
```

The PowerShell wrapper performs the same setup:

```powershell
.\scripts\setup.ps1
.\scripts\demo.ps1
```

If local policy blocks scripts, allow them only for the current PowerShell process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup.ps1
```

### Linux / macOS

```bash
python3 tasks.py setup
python3 tasks.py demo
```

Or use the wrappers:

```bash
./scripts/setup.sh
./scripts/demo.sh
```

If archive extraction removed executable bits, invoke them through Bash:

```bash
bash scripts/setup.sh
bash scripts/demo.sh
```

### What setup changes

`tasks.py setup`:

1. Rejects Python versions older than 3.11.
2. Creates `.venv` when its Python executable is absent.
3. Upgrades pip inside `.venv`.
4. Installs the project in editable mode with the `dev` dependency group.
5. Copies `.env.example` to `.env` only when `.env` does not already exist.

It never overwrites an existing `.env`. Generated run bundles and caches live in
`.adversaryflow/` and are also preserved by `python tasks.py clean`.

### Verify the guided installation

**Windows**

```powershell
.\.venv\Scripts\python.exe -m adversaryflow.cli --version
.\.venv\Scripts\python.exe -m adversaryflow.cli doctor --demo
.\.venv\Scripts\python.exe -m adversaryflow.cli validate-request --request examples\apt29_request.json
```

**Linux / macOS**

```bash
.venv/bin/python -m adversaryflow.cli --version
.venv/bin/python -m adversaryflow.cli doctor --demo
.venv/bin/python -m adversaryflow.cli validate-request --request examples/apt29_request.json
```

Expected results include version `0.3.0`, “Ready for deterministic demo mode,”
and “Valid request.” The demo produces a report, a neighboring trace, a durable
run bundle, and reusable node-cache entries.

## Method B: minimal runtime virtual environment

Use this when you want the source checkout and examples but do not need pytest or Ruff.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
Copy-Item .env.example .env
adversaryflow --version
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
cp .env.example .env
adversaryflow --version
```

Use `python -m pip`, not a bare `pip`, when diagnosing environments; it guarantees
that pip belongs to the displayed interpreter. Installation with `.` copies the
current source into the environment. Use `-e .` for an editable developer install.

To work without activation, call `.venv\Scripts\adversaryflow.exe` on Windows or
`.venv/bin/adversaryflow` on Unix.

## Method C: pipx CLI installation

Install pipx according to its platform documentation, then run this from the checkout:

```bash
pipx install .
adversaryflow --version
adversaryflow init --output scenario-request.json
```

`pipx` exposes the command globally while isolating dependencies. Repository
examples are not installed as working-directory files, so use `adversaryflow init`
or copy an example before leaving the checkout. To upgrade after pulling new source:

```bash
pipx reinstall adversaryflow
```

## Method D: build and install a wheel

This method is appropriate for release engineering and controlled deployment.

```bash
python -m pip install build
python -m build
python -m pip install dist/adversaryflow-0.3.0-py3-none-any.whl
```

`python -m build` creates both a wheel and source distribution in `dist/`. The
wheel includes runtime prompts and Python modules. Repository examples, scripts,
and developer tests are not installed into the environment as command-line assets.

Validate a wheel in a fresh environment before distributing it:

```bash
python -m venv wheel-check
wheel-check/bin/python -m pip install dist/adversaryflow-0.3.0-py3-none-any.whl
wheel-check/bin/python -m adversaryflow.cli doctor --demo
```

On Windows replace `wheel-check/bin/python` with
`wheel-check\Scripts\python.exe`.

The build configuration excludes `.env`, `.claude`, `.adversaryflow`, `.venv`,
and `.test-tmp` from distributions. Always inspect release artifacts anyway:

```bash
python -m zipfile -l dist/adversaryflow-0.3.0-py3-none-any.whl
```

## Offline installation

On a connected build machine with the same target operating system and Python
version, create a wheelhouse containing the project and all dependencies:

```bash
python -m pip wheel --wheel-dir wheelhouse .
```

Transfer `wheelhouse/` to the offline machine. Then create an environment and
install without contacting an index:

```bash
python -m venv .venv
.venv/bin/python -m pip install --no-index --find-links wheelhouse adversaryflow
```

Use `.venv\Scripts\python.exe` on Windows. Retain the wheelhouse and record its
hashes for reproducible deployments. Binary dependencies make a wheelhouse
platform- and interpreter-specific.

## Method E: Docker

Build the image from the repository root:

```bash
docker build -t adversaryflow:local .
docker run --rm adversaryflow:local --version
docker run --rm adversaryflow:local doctor --demo
```

The image runs as non-root UID `10001`, uses `/work` as its working directory,
and includes examples under `/app/examples`. An ephemeral demo is:

```bash
docker run --rm adversaryflow:local generate --request /app/examples/tabletop_request.json --output /work/scenario.html --demo
```

The files disappear when that container exits. Use a named volume for portable
persistence across Windows, macOS, and Linux:

```bash
docker volume create adversaryflow-data
docker run --rm --volume adversaryflow-data:/work adversaryflow:local generate --request /app/examples/tabletop_request.json --output /work/scenario.html --store-dir /work/.adversaryflow --demo
docker run --rm --volume adversaryflow-data:/work adversaryflow:local storage list --store-dir /work/.adversaryflow
```

For live operation, pass configuration without baking secrets into the image:

```bash
docker run --rm --env-file .env --volume adversaryflow-data:/work adversaryflow:local doctor --check-network
```

To use a host request and receive host files, bind-mount a directory that UID
`10001` can write. Linux example:

```bash
mkdir -p work
sudo chown 10001:10001 work
cp examples/tabletop_request.json work/request.json
docker run --rm --env-file .env --volume "$PWD/work:/work" adversaryflow:local generate --request /work/request.json --output /work/scenario.html --store-dir /work/.adversaryflow --demo
```

If organization policy forbids changing ownership, run with a mapped host UID/GID
and ensure the mounted directory is writable:

```bash
docker run --rm --user "$(id -u):$(id -g)" --volume "$PWD/work:/work" adversaryflow:local generate --request /work/request.json --output /work/scenario.html --store-dir /work/.adversaryflow --demo
```

Docker Desktop sharing and host ACLs can also block bind-mount writes. A named
volume avoids most cross-platform permission differences.

## Upgrade

Before upgrading a production installation:

1. Back up the durable store, normally `.adversaryflow/runs/`.
2. Read `CHANGELOG.md` and `STORAGE.md`.
3. Update source or install the new wheel.
4. Run `adversaryflow storage status`.
5. Test `adversaryflow storage migrate` against a copied store first.
6. Run `adversaryflow doctor` and a deterministic demo.

Repository editable install:

```bash
git pull --ff-only
python tasks.py setup
python tasks.py check
python tasks.py demo
```

Wheel install:

```bash
python -m pip install --upgrade dist/adversaryflow-NEW_VERSION-py3-none-any.whl
```

## Uninstall

For a virtual-environment installation, deactivate it and remove only that exact
`.venv` directory when it is no longer needed. For pipx:

```bash
pipx uninstall adversaryflow
```

Uninstalling the package does not remove reports, `.env`, or `.adversaryflow`.
Preserve or delete those separately according to the exercise retention policy.

## Installation troubleshooting

### `python` or `py` is not recognized

Install Python 3.11+, reopen the terminal, and retry the version check. On Unix,
the command is usually `python3` rather than `python`.

### `No module named venv` or `ensurepip`

Install the operating system's venv package, such as `python3.11-venv`, then
recreate `.venv`.

### PowerShell refuses `Activate.ps1`

Activation is optional. Use `.venv\Scripts\python.exe -m adversaryflow.cli ...`,
or temporarily enable scripts only for the current process.

### Dependency download or certificate failure

Confirm proxy and certificate settings for pip. Enterprise environments may need
an approved package mirror or offline wheelhouse. Do not disable TLS verification.

### The `adversaryflow` command is not found after installation

Activate the intended environment or use `python -m adversaryflow.cli`. Check
`python -m pip show adversaryflow` to confirm which interpreter owns the install.

### A Docker bind mount returns `PermissionError`

Ensure the mount is writable by UID `10001`, map the host UID/GID on Linux, or
use a named Docker volume.

### A partially created `.venv` blocks setup

Confirm it contains `Scripts\python.exe` on Windows or `bin/python` on Unix.
If it does not, remove only that project-local `.venv` and rerun setup.
