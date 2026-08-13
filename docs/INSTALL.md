# Installation and first-user journey

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

The same procedure is supported on current 64-bit Debian and Ubuntu releases. Python 3.11 or newer is required.

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

## Supported platform matrix

| Platform | Install path | CI coverage |
|---|---|---|
| Windows | `scripts/install.ps1` | Windows runner |
| Debian | `scripts/install.sh` | Debian container |
| Ubuntu | `scripts/install.sh` | Ubuntu runner |
| Kali | `scripts/install.sh` | Kali container |
