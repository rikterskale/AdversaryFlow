# Installation and first-user journey

AdversaryFlow requires Python 3.11 or newer and supports Windows, Debian, Ubuntu, and Kali. The installers create or reuse a project-local `.venv`, install the package, and run `doctor --fix`.

## Windows

```powershell
.\scripts\install.ps1
.\.venv\Scripts\adversaryflow.exe doctor
.\.venv\Scripts\adversaryflow.exe demo
```

For contributors who need test and security tools, use `.\scripts\install.ps1 -Dev`.

## Debian and Ubuntu

```bash
bash scripts/install.sh
.venv/bin/adversaryflow doctor
.venv/bin/adversaryflow demo
```

For contributors, use `bash scripts/install.sh --dev`.

Python 3.11 or newer is required.

## Kali Linux

Use a virtual environment rather than installing into the system Python:

```bash
bash scripts/install.sh
.venv/bin/adversaryflow doctor --json
.venv/bin/adversaryflow demo
```

Kali-specific tools are not required for the offline demo. AdversaryFlow treats Kali as a supported operator workstation, while its safe catalog controls which emulation capabilities can run.

## Docker

```bash
docker build -t adversaryflow .
docker run --rm -v "$PWD/artifacts:/app/artifacts" adversaryflow doctor
```

The offline demo requires no AI provider key or external network access. The installers reuse an existing `.venv`, upgrade pip, install the runtime package, and run `doctor --fix` to create local artifact folders.

If installation or startup fails, run the guided diagnostics:

```bash
adversaryflow doctor
adversaryflow doctor --fix --json
adversaryflow support-bundle
```

`doctor --fix` only creates local `artifacts/` folders. It does not change system settings, install software, or contact an AI provider. Follow each `NEXT` remediation line for missing Python, dependencies, invalid RoE, catalog, or loopback issues. Attach the generated support bundle when requesting help.

## Complete offline journey

After installation, validate the full local workflow:

```bash
adversaryflow provider validate
adversaryflow provider diagnose
adversaryflow campaign --actor APT29 --objective "validate endpoint process visibility"
adversaryflow campaign --actor APT29 --objective "validate endpoint process visibility" --approve --approver manager@example.test
```

If a hosted provider is unavailable, rerun with `--fallback-offline` to preserve a safe local rehearsal. Use `adversaryflow campaign cancel --campaign-id campaign-... --reason "operator requested stop"` for an incomplete saved campaign; completed campaigns remain immutable.

## Release signatures

Release builds always include SHA-256 manifests. For publication signing, set `ADVERSARYFLOW_RELEASE_GPG_KEY` to an available GPG key ID before running `python scripts/release.py`; this produces `SHA256SUMS.json.asc`. Verify it with `verify_release_signature` from `scripts.release` using the publisher's public keyring.

Download release artifacts from the [releases page](https://github.com/rikterskale/AdversaryFlow/releases), verify `SHA256SUMS.json`, and install the wheel with `python -m pip install adversaryflow-0.2.3-py3-none-any.whl`. Verify `SHA256SUMS.json.asc` only when the release includes that signature.

## Supported platform matrix

| Platform | Install path | CI coverage |
|---|---|---|
| Windows | `scripts/install.ps1` | Windows runner |
| Debian | `scripts/install.sh` | Debian container |
| Ubuntu | `scripts/install.sh` | Ubuntu runner |
| Kali | `scripts/install.sh` | Kali container |

Continue with [USAGE.md](USAGE.md), [CLI_REFERENCE.md](CLI_REFERENCE.md), and [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
