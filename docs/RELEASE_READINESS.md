# New-user release-readiness standard

This is a mandatory release gate, not a target. A release is ready only when CI proves every checkpoint below from built artifacts in fresh environments. A coverage percentage, a successful import, or a developer-machine run cannot waive a failed checkpoint. There are no exceptions.

## Proven installation

Each wheel, source distribution, and source ZIP must install into a new environment on Windows and Linux. The installed CLI must pass `adversaryflow doctor --json`, including its supported-platform, Python, dependency, RoE, ability-catalog, execution-adapter readiness, loopback, and offline-mode checks. Adapter readiness must identify the selected built-in adapter and its exact boundary. IDPT release validation additionally requires the reviewed commit, clean checkout, content version, Node version, and fixed scenario.

## Guided troubleshooting

The installed CLI must run `doctor --fix --json`, `provider validate`, `provider diagnose`, `support-bundle`, and `guide`. The campaign guide must direct a new user to scope review, explicit approval, reports, provider diagnostics, and the local manager.

## Full-feature validation

The canonical clean wheel installation must execute every supported user-facing operation: RoE validation, capability and adapter inspection, offline and provider-configured drafting, campaign lifecycle decisions, approval and fixed local-synthetic emulation, reports, provider profiles and policy, provider diagnostics, MITRE dry-run planning, support bundles, the local demo, and static manager assets. Every parser option must be represented by an executable test or an explicit expected-failure recovery test; documentation coverage alone is insufficient.

## Tested recovery paths

The release journey must demonstrate `doctor --fix`, `--fallback-offline` when a provider is invalid, rejection, cancellation, reset with typed confirmation, an invalid provider configuration, missing credentials, and a missing MITRE technique. Each recovery must return an actionable error and must not bypass RoE approval or the selected fixed execution boundary.

## Documentation

The README and installation guide must document the guide, local manager, troubleshooting commands, offline fallback, campaign cancellation, and the complete offline journey. CI checks these documents for the required first-user instructions.

## CI enforcement

The `new-user-release-standard` CI job builds release artifacts and runs `scripts/release_readiness.py` on Ubuntu and Windows. It is required before release tagging. Any failed installation, operation, recovery path, static asset, report, documentation assertion, or parser-surface assertion fails the build.
