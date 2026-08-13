# Installation and first-user journey

## Windows

```powershell
.\scripts\install.ps1
.\.venv\Scripts\python.exe -m adversaryflow doctor
.\.venv\Scripts\python.exe -m adversaryflow demo
```

## Debian and Ubuntu

```bash
bash scripts/install.sh
.venv/bin/python -m adversaryflow doctor
.venv/bin/python -m adversaryflow demo
```

The same procedure is supported on current 64-bit Debian and Ubuntu releases. Python 3.11 or newer is required.

## Kali Linux

Use a virtual environment rather than installing into the system Python:

```bash
bash scripts/install.sh
.venv/bin/python -m adversaryflow doctor --json
.venv/bin/python -m adversaryflow demo
```

Kali-specific tools are not required for the offline demo. AdversaryFlow treats Kali as a supported operator workstation, while its safe catalog controls which emulation capabilities can run.

## Docker

```bash
docker build -t adversaryflow .
docker run --rm -v "$PWD/artifacts:/app/artifacts" adversaryflow doctor
```

The offline demo requires no AI provider key or external network access. If installation fails, run `adversaryflow doctor --json` and attach the output of `adversaryflow support-bundle` to a support request.

## Supported platform matrix

| Platform | Install path | CI coverage |
|---|---|---|
| Windows | `scripts/install.ps1` | Windows runner |
| Debian | `scripts/install.sh` | Debian container |
| Ubuntu | `scripts/install.sh` | Ubuntu runner |
| Kali | `scripts/install.sh` | Kali container |
