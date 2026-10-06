# Structured intelligence import

The welcome screen can compare a bounded CSV, ATT&CK Navigator layer, or STIX
2.1 bundle with an ATT&CK group or campaign. The importer returns an
AdversaryFlow intelligence-review record containing:

- a SHA-256 digest and source label/HTTPS URL for the imported file;
- each imported technique as a `needs_review` candidate;
- technique metadata and the current catalog source when the ID exists in the
  selected ATT&CK data version, including a format-neutral ability summary with
  fidelity, platform, executor, safety class, and content digest; and
- `report_only`, `attack_only`, and `both` technique sets.

Navigator scores are not interpreted as confidence. The importer does not
turn ATT&CK technique descriptions or relationship edges into report evidence.
An ATT&CK Navigator layer and STIX bundle establish structured technique
mappings; they do not establish a report quotation. CSV can carry optional
`evidence_quote`, `procedure`, `source_name`, `source_url`, `confidence`,
`platform`, `technique_name`, and `tactic` columns. The primary technique column
may be named `technique_id`, `attack_id`, `attack_technique`, `external_id`, or
`id`. Confidence must be an explicit number from 0 to 1.

Every candidate starts in `needs_review`. The operator may accept or reject it
in the UI, download the review record, and attach accepted mappings to the
planning workspace. An attached mapping appears in schema 3.0 plan JSON only
when the plan actor matches the actor selected during import. Procedure evidence
keeps the quote, source digest, technique mapping, and reviewer/acceptance
metadata. Saving that plan as an engagement creates a server-side revision.
The reviewer name and timestamp remain operator-entered metadata, not an
authenticated signature; the plan JSON can be edited after export.

Imports are limited to 16 MiB and 4,000 unique candidates. Only HTTPS source
URLs are accepted. Imported text is rendered as text, and this endpoint does
not fetch the supplied URL or run commands. Schema 2.0 plans remain supported
for plans without accepted procedure evidence; schema 3.0 is used when accepted
procedure evidence is attached.

The API accepts raw file content at `POST /api/intelligence/import`. Query
parameters select `domains`, `actor_stix_id`, `source_kind` (`csv` or `json`),
`source_name`, and optionally `source_url`; the standard CSRF and remote bearer
requirements apply.

Current code-backed catalog entries are projected into the separate
`schemas/adversaryflow-ability.schema.json` contract. Those projections carry
`review_status: unassessed`; they are groundwork for versioned content packs,
not assertions that the entries have passed a new content-review process.

Attached procedures use compound actor/candidate identity, so comparing the
same source against two actors retains independent reviewed evidence. Rejection
immediately revokes that actor/source attachment, including recovery snapshots.
Acceptance never autoattaches a new candidate: choose **Attach accepted
procedures**. Reimport reflects existing accepted attachments, and an all-rejected
review can still synchronize an empty accepted set.
