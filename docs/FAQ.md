# Frequently asked questions

## Does AdversaryFlow execute exploits or arbitrary commands?

No. The ability catalog models synthetic actions only. It does not provide operator-supplied command execution or a remote execution channel. Allowed ability network scope is `none` or `loopback`.

## Can the browser manager approve or run a campaign?

Yes, but only for the fixed local-synthetic path. The loopback-only manager can run local diagnostics, create drafts, inspect campaigns, record rejection or cancellation, and approve and run a reviewed campaign after exact RoE-approver identity, campaign-specific typed confirmation, and integrity checks. `local-behavioral` and `idpt-local` execution remain CLI-only.

## Is a provider key required?

No. Offline mode is the default and needs no key. An OpenAI-compatible provider is optional. `provider validate` does not send a request; `provider test` is the provider command that sends one planning request.

## What happens when a provider fails?

Use `adversaryflow provider diagnose`. A campaign can be rerun with `--fallback-offline` to create a safe local rehearsal draft.

## Can I edit a campaign after approving it?

No. Resumption checks the stored draft, RoE, and catalog hashes. Create a new reviewed draft when scope changes.

## Where are campaign artifacts stored?

Campaign drafts use `artifacts/campaigns` by default; local synthetic runs use `artifacts/runs`; support bundles use `artifacts/support`. Commands expose options to choose these roots where applicable.

## How do I stop a campaign?

Use `campaign cancel --campaign-id campaign-... --reason "Operator requested stop"` for an incomplete campaign. Completed campaigns cannot be cancelled. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
