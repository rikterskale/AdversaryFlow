# New-user release-readiness standard

This is a mandatory release gate, not a target. A release is ready only when CI proves every checkpoint below from built artifacts in fresh environments. A coverage percentage, a successful import, or a developer-machine run cannot waive a failed checkpoint. There are no exceptions.

## Proven installation

Each wheel, source distribution, and source ZIP must install into its own new environment on Windows and Linux. The journey runs outside the source checkout, removes `PYTHONPATH`/`PYTHONHOME` influence, proves the imported module comes from the temporary environment, and validates both the installed `adversaryflow` console script and `python -m adversaryflow`. The installed CLI must pass `adversaryflow doctor --json`, including its supported-platform, Python, dependency, RoE, ability-catalog, execution-adapter readiness, loopback, and offline-mode checks. Adapter readiness must identify the selected built-in adapter and its exact boundary. IDPT release validation additionally requires the reviewed commit, clean checkout, content version, Node version, and fixed scenario.

## Guided troubleshooting

The installed CLI must run `doctor --fix --json`, `provider validate`, `provider diagnose`, `support-bundle`, and `guide`. The campaign guide must direct a new user to scope review, explicit approval, reports, provider diagnostics, and the local manager.

## Full-feature validation

The release-readiness standard requires the canonical clean wheel installation to exercise every supported user-facing operation: RoE validation, capability and adapter inspection, offline and provider-configured drafting, campaign lifecycle decisions, approval and fixed local-synthetic emulation, reports, provider profiles and policy, provider diagnostics, MITRE dry-run planning, support bundles, the local demo, and static manager assets. The clean artifact journey in `scripts/artifact_journey.py` exercises its explicitly listed subset; any operation not included there must be covered by an executable release-artifact test or an explicit expected-failure recovery test. Documentation coverage alone is insufficient.

## Tested recovery paths

The release journey must demonstrate `doctor --fix`, `--fallback-offline` when a provider is invalid, rejection, cancellation, reset with typed confirmation, an invalid provider configuration, missing credentials, and a missing MITRE technique. Each recovery must return an actionable error and must not bypass RoE approval or the selected fixed execution boundary.

## Documentation

The README and installation guide must document the guide, local manager, troubleshooting commands, offline fallback, campaign cancellation, and the complete offline journey. CI checks these documents for the required first-user instructions.

## CI enforcement

The `new-user-release-standard` CI job builds release artifacts and runs `scripts/release_readiness.py` on Ubuntu and Windows. Separate `first-user-windows` and `first-user-linux` jobs invoke the documented installers from outside the checkout for Windows, Debian, Ubuntu, and Kali, rerun each installer against the same environment, and execute the installed doctor and demo commands. The source-test matrix covers Python 3.11, 3.12, 3.13, and 3.14 without multiplying every release journey across every OS/version combination. These jobs are required before release tagging. Any failed installation, operation, recovery path, static asset, report, documentation assertion, or parser-surface assertion fails the build.
