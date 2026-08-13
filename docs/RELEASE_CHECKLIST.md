# Release checklist

## Before tagging

- [ ] Confirm `pyproject.toml` version and `CHANGELOG.md` release entry match.
- [ ] Run `python -m pytest -q --cov=adversaryflow --cov-branch --cov-fail-under=95`.
- [ ] Run `python scripts/validate_documentation.py`.
- [ ] Build and verify artifacts with `python scripts/release.py artifacts/release`.
- [ ] Run `python scripts/release_readiness.py artifacts/release` in a network-enabled environment.
- [ ] Confirm no credentials, target data, or raw provider responses are included in release material.

## Tag and publish

- [ ] Push `main` and create a matching `vMAJOR.MINOR.PATCH` tag.
- [ ] Confirm the release workflow publishes the wheel, source distribution, source ZIP, `SHA256SUMS.json`, and `sbom.cdx.json`.
- [ ] If signing was configured, confirm `SHA256SUMS.json.asc` is present and verifies against the publisher keyring.

## After publishing

- [ ] Install the released wheel in a fresh environment and run `adversaryflow doctor --json`.
- [ ] Run the offline demo and confirm a telemetry-gap report is produced.
- [ ] Confirm the release notes link to the changelog and the release assets.
