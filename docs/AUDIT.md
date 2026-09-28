# Audit log

The local SQLite store keeps an append-only, hash-chained audit stream. Events
are written in the same transaction as engagement revision saves and ability
backlog ownership/status changes. Successful execution-kit, report, and Atomic
playbook exports also create events before the download is returned.

Each record includes a monotonically increasing sequence, event ID and time,
event type, principal label, entity/revision, a bounded structured payload,
the previous event digest, and its own SHA-256 digest. Payloads record hashes,
scope digests, formats, sizes, and counts; they do not contain commands or
receipt payloads. `GET /api/audit-events` verifies the full chain before it
returns a page. It returns HTTP 503 if verification fails or the audit store
reaches its event cap. The current cap is 200,000 records; events are not
silently pruned.

The `principal` is the plan's operator label for a saved plan/export or
`unknown` for service-driven changes. It is not an authenticated identity.
Identity-provider login, role enforcement, project isolation, and second-person
approval remain control-plane work. The digest chain detects changes to stored
events, but an administrator who can rewrite the SQLite database can recompute
the chain or truncate its tail. Export periodic copies to an independently
controlled audit destination for tamper resistance.

## Event types

| Event | Recorded fields |
| --- | --- |
| `engagement_revision_saved` | Plan digest, ATT&CK data version, scope digest, content-pack-set digest, and technique count |
| `execution_kit_exported` | Plan digest, platform, artifact name, and byte size |
| `engagement_report_exported` | Plan digest, report format, ATT&CK version, platform, and byte size |
| `atomic_playbook_exported` | Plan digest, platform, included-ability count, backlog count, and installed-pack count |
| `ability_backlog_generated` | Number of backlog records and digest of their IDs |
| `ability_backlog_updated` | Previous/new owner and status for the backlog item |

Scope edits are represented by the digest in a saved revision. Edits that have
not been saved are not server-side events because the browser keeps its
working plan locally.
