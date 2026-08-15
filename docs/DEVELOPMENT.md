# Development

## Environment

The project requires Python 3.11 or newer and uses setuptools. Install the development dependencies with the platform-specific installer:

```powershell
./scripts/install.ps1 -Dev
```

```bash
bash scripts/install.sh --dev
```

Both scripts create or reuse `.venv`, install the package in editable mode, and run `adversaryflow doctor --fix`.

## Validation

```powershell
python -m pytest -q --cov=adversaryflow --cov-branch --cov-fail-under=95
python -m adversaryflow doctor --json
```

If pytest cannot create its default Windows temporary directory, keep the temporary files inside the repository and rerun with an explicit basetemp:

```powershell
python -m pytest -q --basetemp .pytest-tmp --cov=adversaryflow --cov-branch --cov-fail-under=95
```

The directory is local test output; remove it after the run if it is not needed.

The CI workflow runs tests on Windows and Ubuntu with Python 3.11 and 3.12, plus release-readiness and security jobs. The current suite meets the configured 95% combined line-and-branch coverage threshold.

## Release artifacts

```powershell
python -m pip install build
python scripts/release.py artifacts/release
python scripts/artifact_journey.py artifacts/release
python scripts/release_readiness.py artifacts/release
```

The release script builds a wheel, source distribution, source ZIP, SHA-256 manifest, and CycloneDX SBOM. Set `ADVERSARYFLOW_RELEASE_GPG_KEY` before running the release script to create an armored signature for `SHA256SUMS.json`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution boundaries and [RELEASE_READINESS.md](RELEASE_READINESS.md) for the CI acceptance standard.
