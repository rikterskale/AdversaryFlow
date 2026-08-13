# Usage

## Safe offline campaign flow

1. Check the local environment: `adversaryflow doctor --json`.
2. Generate a reviewable draft: `adversaryflow campaign --actor "APT29" --objective "validate endpoint process visibility"`.
3. Inspect the returned campaign ID: `adversaryflow campaign inspect --campaign-id campaign-...`.
4. The RoE-named approver may authorize local synthetic emulation: `adversaryflow campaign --campaign-id campaign-... --approve --approver "manager@example.test"`.
5. Review `campaign-report.md`, `campaign-report.html`, and `telemetry-gap-report.json` in the resulting artifacts.

Draft resumption verifies the saved plan, RoE, and ability-catalog hashes. If scope changes, create a new draft rather than changing an approved record.

## Guided experience

Run `adversaryflow guide --interactive` for terminal guidance or `adversaryflow manager --open` for the loopback-only browser workspace. The browser can create offline drafts, inspect records, and record rejection or cancellation; it cannot approve or execute campaigns.

## Hosted-provider recovery

Offline is the default. For an OpenAI-compatible provider, use `adversaryflow provider configure`, then `provider validate`, then `provider test`. If a hosted campaign draft fails, use `--fallback-offline` to create a local rehearsal draft.

See [CLI_REFERENCE.md](CLI_REFERENCE.md) for exact options and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for recovery paths.
