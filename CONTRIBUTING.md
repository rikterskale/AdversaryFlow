# Contributing

AdversaryFlow accepts improvements that preserve its simulation-only, RoE-gated safety model.

## Local setup

Use Python 3.11 or newer. On Windows, run `./scripts/install.ps1 -Dev`; on Debian, Ubuntu, or Kali, run `bash scripts/install.sh --dev`. Then run:

```powershell
python -m pytest -q --cov=adversaryflow --cov-branch --cov-fail-under=95
python -m adversaryflow doctor --json
```

## Change expectations

- Keep browser operations loopback-only; approval and emulation remain CLI-only.
- Do not add exploitation, arbitrary command execution, credential access, persistence, evasion, lateral movement, or unrestricted networking.
- Add tests for new behavior and retain the coverage gate.
- Update source-confirmed documentation when commands, defaults, safety boundaries, or recovery paths change.

## Pull requests

Describe the user impact, validation performed, and any safety implications. Do not include credentials, provider responses, or sensitive target data.
