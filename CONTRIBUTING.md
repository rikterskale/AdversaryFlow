# Contributing to AdversaryFlow

Thank you for improving AdversaryFlow.

By participating you agree to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and
[ACCEPTABLE_USE.md](ACCEPTABLE_USE.md). Catalog changes must keep the live-mutator
invariants in `tests/test_catalog_safety.py` passing: no SAM exports, account
or service creation, session locks, IMDS queries, or third-party HTTP fetches.

## Development setup

Frontend development requires Node.js 22.22.2+ or 24.15.0+. Use Node 24.15+
from the 24.x line when reproducing package builds; it matches the pinned
container build environment. Install the reviewed dependency graph without
lifecycle scripts, then run the complete frontend gate:

```bash
npm ci --ignore-scripts
npm run check:frontend
npm run check:frontend-assets
```

`check:frontend` type-checks the TypeScript source, builds the stable browser
assets, and runs the Vitest suite. `check:frontend-assets` fails when those
generated files differ from Git. Commit regenerated `frontend/index.html`,
`frontend/styles.css`, `frontend/app.js`, and `frontend/favicon.svg` with the
source change that produced them.

```bash
./install.sh
.venv/bin/python -m unittest discover --verbose
node --check frontend/app.js
bash -n install.sh run.sh
```

Browser coverage uses Playwright:

```bash
npx playwright install --with-deps chromium
npm run test:e2e
```

Lint and type checks are configured in `pyproject.toml` and run as their own
CI job. Install the pinned tooling, then run both locally:

```bash
.venv/bin/python -m pip install --require-hashes --requirement requirements-dev.lock
.venv/bin/ruff check .
.venv/bin/mypy
```

Both must report zero findings before a pull request is opened.

On Windows, use `install.ps1` and `.venv\Scripts\python.exe`.

## Pull requests

Open a pull request against `main`; do not push to it directly. A workflow
enables auto-merge on the maintainer's own pull requests, so once every
required check is green the branch merges itself by rebase. Merged branches are
not deleted automatically — remove yours with
`git push origin --delete <branch>`.

- Keep changes focused and explain the user-visible outcome.
- Add or update tests for behavior changes.
- Update `README.md`, API/export schemas, and `CHANGELOG.md` when contracts change.
- Preserve exact-platform behavior: a plan must never silently substitute another host OS.
- Keep the catalog size and entry-shape invariant tests passing.
- Include screenshots or a short recording for material UI changes.

All changes require a passing CI matrix and owner review before merge.

## Versioning

AdversaryFlow uses semantic versioning. Breaking API/export changes require a major version; compatible features require a minor version; compatible fixes require a patch version.

