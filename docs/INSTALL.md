# Installation and first-user journey

AdversaryFlow supports Windows, Debian, Ubuntu, and Kali with Python 3.11 through 3.14. Releases are downloaded from [GitHub Releases](https://github.com/rikterskale/AdversaryFlow/releases); the project is not currently published on PyPI.

## Prerequisites

| Platform | Required software |
|---|---|
| Windows | Python 3.11-3.14 from [python.org](https://www.python.org/downloads/windows/) with `pip` and `venv` |
| Debian or Ubuntu | `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip` |
| Kali | `sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip` |

Git is needed only for a source checkout. An internet connection is needed to download the release and resolve its Python dependency during installation. The offline demo itself needs no API key and makes no external network request.

## End-user release installation

Every GitHub release contains two end-user paths:

- **Wheel:** the quickest install into any virtual environment. Download `adversaryflow-*-py3-none-any.whl` and `SHA256SUMS.json`.
- **Source ZIP:** includes the platform installers and is useful when you want a self-contained extracted project folder. Download `adversaryflow-source.zip` and `SHA256SUMS.json`.

The `.tar.gz` source distribution is validated as a release artifact but is primarily a Python packaging format. Contributors should use a Git checkout instead.

### Verify the downloaded hash

From the directory containing the wheel and `SHA256SUMS.json`, use PowerShell:

```powershell
$wheel = Get-ChildItem .\adversaryflow-*-py3-none-any.whl | Select-Object -First 1
$manifest = Get-Content .\SHA256SUMS.json -Raw | ConvertFrom-Json
$expected = ($manifest.artifacts | Where-Object name -eq $wheel.Name).sha256
if (-not $expected -or (Get-FileHash $wheel -Algorithm SHA256).Hash.ToLower() -ne $expected) { throw "Wheel hash verification failed" }
```

On Linux:

```bash
wheel="$(find . -maxdepth 1 -name 'adversaryflow-*-py3-none-any.whl' -print -quit)"
python3 -c 'import hashlib,json,pathlib,sys; p=pathlib.Path(sys.argv[1]); m=json.load(open("SHA256SUMS.json", encoding="utf-8")); expected=next((a["sha256"] for a in m["artifacts"] if a["name"]==p.name), None); actual=hashlib.sha256(p.read_bytes()).hexdigest(); assert expected and actual==expected, "wheel hash verification failed"' "$wheel"
```

If a release also provides `SHA256SUMS.json.asc`, verify that optional signature with the publisher's public key. A missing `.asc` file does not invalidate an unsigned development release; the SHA-256 manifest remains required.

### Install the wheel

Windows PowerShell:

```powershell
python -m venv .venv
$wheel = (Get-ChildItem .\adversaryflow-*-py3-none-any.whl | Select-Object -First 1).FullName
.\.venv\Scripts\python.exe -m pip install $wheel
.\.venv\Scripts\adversaryflow.exe doctor --json
.\.venv\Scripts\adversaryflow.exe demo
```

Debian, Ubuntu, or Kali:

```bash
python3 -m venv .venv
wheel="$(find . -maxdepth 1 -name 'adversaryflow-*-py3-none-any.whl' -print -quit)"
.venv/bin/python -m pip install "$wheel"
.venv/bin/adversaryflow doctor --json
.venv/bin/adversaryflow demo
```

These commands do not require virtual-environment activation. A successful `doctor` reports the supported platform, Python, dependency, RoE, catalog, execution-adapter, loopback, and offline checks. The demo writes local simulation evidence and a telemetry gap report under `artifacts/`.

### Install the release source ZIP

Extract `adversaryflow-source.zip`, enter the extracted `adversaryflow` directory, and run:

```powershell
.\scripts\install.ps1
.\.venv\Scripts\adversaryflow.exe doctor
.\.venv\Scripts\adversaryflow.exe demo
```

```bash
bash scripts/install.sh
.venv/bin/adversaryflow doctor
.venv/bin/adversaryflow demo
```

The scripts resolve the project directory from their own location, so they also work when called by absolute path from another directory. A normal install is non-editable. Each script creates or reuses the extracted project's `.venv`, upgrades the installed runtime package, and runs `doctor --fix`.

## Source checkout installation

Clone the repository, then use the same runtime installer:

```powershell
git clone https://github.com/rikterskale/AdversaryFlow.git
cd AdversaryFlow
.\scripts\install.ps1
.\.venv\Scripts\adversaryflow.exe demo
```

```bash
git clone https://github.com/rikterskale/AdversaryFlow.git
cd AdversaryFlow
bash scripts/install.sh
.venv/bin/adversaryflow demo
```

Running the installer again is supported and exercises the same idempotent upgrade path used by CI. It does not delete or recreate an existing environment.

## Contributor setup

Contributor mode is intentionally different: it installs the checkout in editable mode with test and security dependencies. See [CONTRIBUTING.md](../CONTRIBUTING.md) for the complete contribution workflow.

```powershell
.\scripts\install.ps1 -Dev
.\.venv\Scripts\python.exe -m pytest -q
```

```bash
bash scripts/install.sh --dev
.venv/bin/python -m pytest -q
```

## Recovery and reruns

If installation or startup fails:

1. Confirm `python --version` on Windows or `python3 --version` on Linux reports 3.11-3.14.
2. Install the platform prerequisite packages above. On Linux, a missing `ensurepip` or venv error normally means `python3-venv` is missing.
3. Rerun the same installer. Repeated invocation is safe and upgrades the existing install.
4. If the installer reports that `.venv` is incomplete, from another platform, or uses incompatible Python, preserve it by renaming it (`Rename-Item .venv .venv-old` or `mv .venv .venv-old`) and rerun. The installer never silently deletes a user environment.
5. Run the guided diagnostics with the environment's executable:

```powershell
.\.venv\Scripts\adversaryflow.exe doctor
.\.venv\Scripts\adversaryflow.exe doctor --fix --json
.\.venv\Scripts\adversaryflow.exe support-bundle
```

```bash
.venv/bin/adversaryflow doctor
.venv/bin/adversaryflow doctor --fix --json
.venv/bin/adversaryflow support-bundle
```

`doctor --fix` only creates local `artifacts/` folders. It does not change system settings, install system software, or contact an AI provider. Follow each `NEXT` remediation line and attach the redacted support bundle when requesting help.

## Complete offline journey

After installation, these activation-not-required commands validate the safe local workflow:

```bash
.venv/bin/adversaryflow provider validate
.venv/bin/adversaryflow provider diagnose
.venv/bin/adversaryflow campaign --actor APT29 --objective "validate endpoint process visibility"
.venv/bin/adversaryflow campaign --actor APT29 --objective "validate endpoint process visibility" --approve --approver manager@example.test
```

On Windows, replace `.venv/bin/adversaryflow` with `.\.venv\Scripts\adversaryflow.exe`. If a configured hosted provider is unavailable, add `--fallback-offline` to preserve a safe local rehearsal. Use `adversaryflow campaign cancel --campaign-id campaign-... --reason "operator requested stop"` for an incomplete saved campaign; completed campaigns remain immutable.

## Supported platform matrix

| Platform | Exact installer exercised by CI | First install and rerun |
|---|---|---|
| Windows | `scripts/install.ps1` | Windows runner |
| Debian | `scripts/install.sh` | Debian 12 container |
| Ubuntu | `scripts/install.sh` | Ubuntu 24.04 container |
| Kali | `scripts/install.sh` | Kali rolling container |

CI also tests the package on every claimed Python minor version from 3.11 through 3.14. Clean release journeys install the wheel, source distribution, and source ZIP into separate temporary virtual environments, then validate both the `adversaryflow` console entry point and `python -m adversaryflow`.

The supported-platform check covers Windows, Debian, Ubuntu, and Kali. The packaged `curated-macos` catalog has fixed read-only actions, but macOS is not accepted by `doctor`; treat that catalog as a separate experimental path until the platform check changes.

Continue with [USAGE.md](USAGE.md), [CLI_REFERENCE.md](CLI_REFERENCE.md), and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
