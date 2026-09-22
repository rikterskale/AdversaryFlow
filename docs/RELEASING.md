# Releasing

1. Update backend.__version__, CHANGELOG.md, schemas, OpenAPI, and docs.
2. Run the complete local verification suite and build in a clean environment.
   Use Node 24.15+ from the 24.x line, install with
   `npm ci --ignore-scripts`, run `npm run check:frontend` followed by
   `npm run check:frontend-assets`, and verify the wheel and source
   distribution with `python scripts/verify_distribution_assets.py`.
3. Merge only after the Linux, Windows, macOS, package-smoke, CodeQL, and build
   jobs pass.
4. Create a reviewed annotated tag matching the package version, such as
   v0.4.0. Never reuse or move a published tag.
5. The release workflow verifies tag/version/changelog identity, restores the
   reviewed frontend dependency graph without lifecycle scripts, runs the
   TypeScript, Vite, Vitest, generated-asset, Python, ruff, and mypy gates,
   builds the wheel and sdist from the fresh browser bundle, verifies the
   packaged frontend bytes, produces CycloneDX SBOM and SHA-256 files, and
   creates GitHub build-provenance attestations.
6. The protected release environment should require approval. GitHub Release
   assets (wheel, sdist, SBOM, SHA256SUMS, and provenance attestations) are
   the distribution. Do not publish to PyPI.
7. Verify release checksums and attestations, then smoke-test --version,
   doctor, /, /api/bootstrap, and /api/health from the released wheel.

GitHub Actions are pinned by commit SHA. Dependabot proposes reviewed action
and Python dependency updates.

