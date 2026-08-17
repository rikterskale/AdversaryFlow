# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses Semantic Versioning.

## [Unreleased]

### Added

- CLI UX: consistent `--json`, `--human`, `--quiet`, and `--no-color` output flags across commands; auto-detected human/colour output on an interactive terminal and clean JSON when piped; severity-coloured safety verdicts; `adversaryflow completion {bash,zsh,fish,powershell}` scripts; an `adversaryflow explain <code>` exit-code reference with documented `ExitCode` constants; will/will-not dry-run banners and step progress indicators on mutating commands; an interactive saved-campaign picker when `--campaign-id` is omitted on a terminal; and a platform-aware, copy-ready remediation summary in `doctor`.
- Manager GUI UX: light/dark/system theme toggle (with `t` shortcut) and theme-aware palette; a persistent local-readiness health badge; keyboard navigation (`1`–`9`) between sections; non-blocking toast notifications; archive free-text plus tag filtering with sortable columns and result counts; a structured scope/telemetry inspect view with an offline-only reminder; and copy-to-clipboard for CLI command blocks including a live "equivalent CLI command" in the draft form.
- A commit-pinned `idpt-local` adapter, fixed Windows collection mapping, derived plan-bound IDPT authorization, verified evidence ingestion, and independent telemetry-gap reporting.
- Offline Sentinel, Defender, Splunk, Elastic, CrowdStrike, and generic telemetry normalization; time-bounded correlation; sensor preflight; JSON/CSV assessment export; immutable gap-derived retests; detection-as-code validation mappings; a campaign coverage dashboard; a reviewed IDPT scenario registry; and fixed read-only Linux/macOS catalogs.

## [0.2.3] - 2026-08-13

### Added

- Guided local manager workflows, provider profiles and policy allowlists, campaign lifecycle recovery, provider recovery coverage, manager approval readiness, and release-readiness enforcement.
- The 95% combined line-and-branch coverage gate and expanded campaign, provider, lifecycle, manager, and resilience test coverage.
- Apache-2.0 licensing, contributor guidance, security policy, code of conduct, CLI reference, operator guides, and module documentation.

## [0.2.2] - 2026-08-13

### Added

- Guided local manager improvements, RoE-aware draft targets, provider profile readiness guidance, and resilience coverage.

## [0.2.1] - 2026-08-13

### Added

- Initial tagged release.

[Unreleased]: https://github.com/rikterskale/AdversaryFlow/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/rikterskale/AdversaryFlow/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/rikterskale/AdversaryFlow/releases/tag/v0.2.2
[0.2.1]: https://github.com/rikterskale/AdversaryFlow/releases/tag/v0.2.1
