# Contributing to AdversaryFlow

Thank you for improving AdversaryFlow.

## Development setup

```bash
./install.sh
.venv/bin/python -m unittest discover --verbose
node --check frontend/app.js
bash -n install.sh run.sh
```

On Windows, use `install.ps1` and `.venv\Scripts\python.exe`.

## Pull requests

- Keep changes focused and explain the user-visible outcome.
- Add or update tests for behavior changes.
- Update `README.md`, API/export schemas, and `CHANGELOG.md` when contracts change.
- Preserve exact-platform behavior: a plan must never silently substitute another host OS.
- Keep the catalog size and entry-shape invariant tests passing.
- Include screenshots or a short recording for material UI changes.

All changes require a passing CI matrix and owner review before merge.

## Versioning

AdversaryFlow uses semantic versioning. Breaking API/export changes require a major version; compatible features require a minor version; compatible fixes require a patch version.

