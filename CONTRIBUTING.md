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
npx playwright install --with-deps chromium firefox webkit
npm run test:e2e
```

The browser suite includes a local Flask service with isolated fixture data, so
install the Python dependencies first. It uses the repository's `.venv` when
available, or `python` on PATH; set `ADVERSARYFLOW_TEST_PYTHON` to override it.

Playwright runs all three browser engines. To run one, use
`npm run test:e2e -- --project=firefox` (or `chromium` / `webkit`). WebKit coverage
is separate from native Safari. The macOS CI job runs the real Safari browser
through Apple's driver; locally, enable it with `safaridriver --enable`, then
run `python scripts/safari_smoke.py`. See [Apple's WebDriver setup](https://developer.apple.com/documentation/safari-developer-tools/macos-enabling-webdriver).

Linux CI uses `xvfb-run --auto-servernum npm run test:e2e -- --headed` to avoid
an [upstream headless WebKit click hang](https://github.com/microsoft/playwright/issues/33057).
Use the same command on Linux when reproducing CI. Retries collect diagnostics,
but flaky tests still fail CI. Browser reports are always uploaded, including
traces of failed attempts that later passed.

For a clean Docker build and first-start check, run
`python scripts/compose_smoke.py --fresh`. Each run creates and removes its own
Compose project and empty cache volume, preserving the regular application cache.

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
