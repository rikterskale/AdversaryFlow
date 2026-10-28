# Command coverage and execution context

The current catalog has 540 technique keys and 1,576 command blocks. The cached
Enterprise ATT&CK bundle used for this change maps 536 techniques across 232
actors. Its SHA-256 is
`dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
ICS and Mobile were not included in this coverage measurement.

Commands now distinguish their executor OS (Windows, Linux or macOS) from their
environment (endpoint, cloud, container or pre-compromise). All 50 previously
non-OS entries have explicit executor recipes. The audit also identified a
Windows-labelled cloud transfer proxy, T1537, and replaced it with read-only,
explicitly labelled cloud account inspection recipes on all three OSes.

The UI chooses an eligible same-OS alternative when one exists. Operators can
pin a particular variant. A pinned variant that disappears stays unavailable
until the operator chooses a current variant; it is never silently substituted.
Availability distinguishes permission requirements, unverified prerequisites,
unsupported coverage and known OS inapplicability. The browser cannot verify
tools, credentials or permissions on the execution host. “Prerequisites
unverified” requires operator review before copying or running a block.

The network guardrail applies only to blocks that can reach beyond loopback.
Loopback-only proxies and bounded exercises stay available under the default
scope and are labelled `loopback_network_activity`; they never contact the
public internet. Network-active cloud, container and remote recipes additionally
declare required credentials, so enabling the network guardrail alone leaves them
“prerequisites unverified” until the operator confirms authorized access.

Tools, required access, environment, purpose and a SHA-256 command identity
survive plan schemas 2.0 and 3.0, workspace recovery, execution kits and reports.
These fields are optional on import so older plans remain readable. Backend
exports rebind to the trusted catalog and respect the selected variant and scope.
Command identities include the body and requirements. Changing the chosen
variant, effective default command or catalog command identity starts a separate
evidence snapshot and archives existing evidence.

All 427 identified applicable Linux/macOS gaps have explicit recipes: native
read-only inspection covers 55 techniques, and 174 techniques have separately
selectable bounded alternatives. These alternatives do not establish equivalent
adversary fidelity. The catalog has 320 bounded exercise IDs across 31 scenario
families; their 960 OS-specific blocks produce self-reported receipts. Synthetic
media, packets, credentials and policy files remain inside temporary exercise
workspaces. No exercise captures actual credentials, media or network traffic.

T1611 has only a Linux container inspection proxy. Windows/macOS remain
unsupported for that recipe. OS-inapplicable techniques and permission-blocked
commands remain visible. Coverage counts do not mean every actor technique is
executable on every OS, or that tools/access are installed and authorized.

## Reproducible verification

`scripts/audit_command_coverage.py`, invoked as a Python module, accepts an
explicit offline `--cache-dir` and `--output`. It validates every catalog block
and ability against their contracts, checks command identities and POSIX shell
syntax, and writes the complete command inventory, availability matrix and
scope/variant decision cases. `--run-bounded` additionally runs only isolated
synthetic fixtures and saves each digest-protected receipt. It never executes
native catalog, cloud or container commands.

`scripts/audit_command_selection.mjs` accepts the generated `catalog.json` and
compares the actual UI resolver with every backend decision. It also round-trips
every command through both plan schemas and the actual browser import contract.
Run it from the repository with the lockfile dependencies installed.

The delivered proof archive includes the cached input, all five chained source
checkpoints, final source, a Git bundle, complete logs, result records, coverage
and individual exercise receipts. `scripts/verify_capability_proof.py` accepts
the archive path, the separately published `--sha256`, and `--repository` for
the Git snapshot. The included Git bundle can restore the snapshot in a separate
repository using Git's bundle/clone commands. The verifier compares every
archived file, stage chain, final source/Git object and required successful check.

SHA-256 and Git objects provide immutable content identities and detect changes
against a separately retained digest. Local files and refs can still be deleted
or replaced. The archive is not independently timestamped, signed by an external
authority or stored on write-once media. Stage timestamps and test results are
local observations; bounded receipts are not independent endpoint attestation.
Native Windows/macOS commands and live cloud/container access still require
target-host validation. The local test process was not network-namespace isolated.
