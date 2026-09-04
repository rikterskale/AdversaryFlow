# Project governance

AdversaryFlow is maintained by the repository owner and designated CODEOWNERS.

- CODEOWNERS review is required for product, API, catalog, packaging, and release changes.
- CI must pass before merge.
- Releases follow `docs/RELEASING.md` and use immutable semantic-version tags.
- Public behavior changes are recorded in `CHANGELOG.md`.
- API and export contract changes update their checked-in schemas in the same pull request.

Repository rulesets and required-check settings are configured in GitHub and should require pull requests, CODEOWNERS approval, the CI test matrix, the build job, and resolution of review conversations on `main`.

