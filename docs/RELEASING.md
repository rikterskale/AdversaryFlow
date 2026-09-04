# Releasing

1. Ensure `backend.__version__` and `CHANGELOG.md` describe the intended release.
2. Run `python -m unittest discover --verbose` and all static checks from CI.
3. Build locally with `python -m build` and test the wheel in a clean virtual environment.
4. Merge through the required review process.
5. Create and push a matching annotated tag such as `v0.2.0`.
6. The release workflow retests, builds the sdist/wheel, and attaches them to a GitHub release.
7. Smoke-test `adversaryflow --version`, `/`, and `/api/health` from the released wheel.

Do not reuse or move a published version tag. Document supported-version or upgrade-policy changes in the changelog and support policy.

