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

## Rebuilding the frontend from a source distribution

The source archive includes the locked npm graph, frontend source, public assets,
and Vite, TypeScript, PostCSS, Tailwind, and Vitest configuration. The distribution
verifier compares these inputs against the checkout in addition to checking the
compiled browser assets in both the wheel and source archive. Wheels continue to
ship only the compiled frontend; users do not need Node to run the application.

Use Node 24.15.0 to match CI, packaging, and container builds. Extract the source
archive into a fresh directory outside the checkout, then change into its top-level
directory. Save hashes of the shipped assets before rebuilding:

```sh
python -c "import hashlib,json; from pathlib import Path; names=('index.html','styles.css','app.js','favicon.svg'); Path('frontend-asset-hashes.json').write_text(json.dumps({n:hashlib.sha256((Path('frontend')/n).read_bytes()).hexdigest() for n in names}))"
npm ci --ignore-scripts
npm run check:frontend
python -c "import hashlib,json; from pathlib import Path; expected=json.loads(Path('frontend-asset-hashes.json').read_text()); changed=[n for n,h in expected.items() if hashlib.sha256((Path('frontend')/n).read_bytes()).hexdigest()!=h]; print('Changed assets:',changed); raise SystemExit(bool(changed))"
```

Success means type checking, the build, and frontend unit tests pass, followed by
`Changed assets: []`. Use this hash comparison in an extracted archive;
`npm run check:frontend-assets` requires the Git checkout. Dependency restoration
requires access to the npm registry or a populated npm cache. Rebuilds do not need
the planner service or the ATT&CK feed.
