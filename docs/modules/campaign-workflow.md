# Campaign workflow

The campaign workflow creates a reviewable draft, records lifecycle decisions, and can perform a RoE-approved run through a selected fixed local adapter.

## Draft and inspect

`campaign --actor ACTOR --objective OBJECTIVE` creates a persisted campaign draft. New drafts require an actor and objective. Draft metadata records plan, RoE, and catalog hashes; a resumed campaign verifies those values before proceeding.

Use `campaign list` to view saved records and `campaign inspect --campaign-id ID` to read a campaign record. Both are read-only.

## Decisions and approval

`campaign reject` records a rejection with the supplied approver and reason. `campaign cancel` records cancellation for an incomplete campaign. `campaign reset --confirm` removes a saved campaign directory only within the configured campaign root.

Approval requires the approver named in the RoE. Add `--approve --approver NAME` to a new or resumed campaign command only after reviewing scope, selected abilities, stop conditions, and integrity.

## Local synthetic result

An approved campaign writes a run directory, progress, normalized events, a manifest, an audit record, telemetry-gap report, and campaign reports. Synthetic loopback markers and IDPT loopback actions are limited to engine-owned `127.0.0.1` listeners.

See [../CLI_REFERENCE.md](../CLI_REFERENCE.md) for exact arguments and [safety-and-emulation.md](safety-and-emulation.md) for enforcement boundaries.
