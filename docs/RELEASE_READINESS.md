# New-user release-readiness standard

A release is ready only when CI proves the following standard using the built wheel, source distribution, and source ZIP in fresh virtual environments. Test coverage is useful feedback, but it is not release readiness on its own.

## Proven installation

Each release artifact must install into a new environment on Windows and Linux. The installed CLI must pass `adversaryflow doctor --json`, including its supported-platform, Python, dependency, RoE, ability-catalog, execution-adapter readiness, loopback, and offline-mode checks. The adapter readiness result must identify only the built-in local-synthetic adapter and the simulation-only boundary.

## Guided troubleshooting

The installed CLI must run `doctor --fix --json`, `provider validate`, `provider diagnose`, `support-bundle`, and `guide`. The campaign guide must direct a new user to scope review, explicit approval, reports, provider diagnostics, and the local manager.

## Full-feature validation

The clean install must run the offline demo, create and approve a persisted campaign, generate reports, expose the guided manager CLI, and validate the campaign guide. These checks prove the documented user path rather than only importing modules.

## Tested recovery paths

The release journey must demonstrate `--fallback-offline` when a provider is invalid, cancellation of an incomplete campaign, and actionable validation output for an unsupported provider. No recovery path may bypass RoE approval or the simulation-only boundary.

## Documentation

The README and installation guide must document the guide, local manager, troubleshooting commands, offline fallback, campaign cancellation, and the complete offline journey. CI checks these documents for the required first-user instructions.

## CI enforcement

The `release-readiness` CI job builds the release artifacts and runs `scripts/release_readiness.py` on Ubuntu and Windows. Treat this job as a required check before release tagging.
