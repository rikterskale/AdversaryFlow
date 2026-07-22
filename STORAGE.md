# Durable storage and caching

AdversaryFlow stores completed runs and reusable cache entries under
`.adversaryflow/` by default. Set `ADVERSARYFLOW_STORE_DIR` or pass `--store-dir`
to use another location. The default directory is ignored by Git because run
artifacts can contain environment details, source material, and model output.

## Run bundle contract

Every successful stored generation creates an immutable directory:

```text
.adversaryflow/
  store.json
  runs/<run-id>/
    manifest.json
    request.json
    scenario-pack.json
    trace.json
    report.md | report.html
  cache/
    nodes/<prefix>/<key>.json
    sources/
      urls/<prefix>/<url-key>.json
      documents/<prefix>/<content-sha256>.json
```

The manifest records the store schema version, run state, provider identity,
request and scenario hashes, cache statistics, and exact byte hashes for every
artifact. Writes use a temporary file and an atomic replacement, so readers do
not observe partially written JSON. Run IDs combine a UTC timestamp, request
hash prefix, and random suffix; an existing run directory is never overwritten.

Use `--no-store` when the caller is responsible for artifact persistence. This
does not disable caching. Use `--no-cache` separately to force an entirely
uncached generation.

## Node cache keys

A model-node entry is reused only when all of these values are identical:

- cache format version;
- node name;
- provider endpoint/model identity (never the API key);
- complete system prompt;
- response JSON Schema;
- canonicalized node input payload.

Only successfully validated structured outputs are cached. Provider failures,
invalid JSON, and schema failures are never stored. `--refresh-nodes` bypasses
reads and replaces successful entries. Every node trace records `hit`, `miss`,
or `refresh` plus its cache key.

## Source cache keys and freshness

The source cache has two layers:

1. A normalized HTTPS URL index points to the latest content SHA-256 and fetch time.
2. The extracted `SourceDocument` is stored by the fetched content SHA-256.

The default freshness lifetime is 86,400 seconds. Configure it with
`ADVERSARYFLOW_SOURCE_CACHE_TTL`; use `0` to make every prior entry stale.
`--refresh-sources` bypasses URL-index reads and writes newly validated content.
Invalid, failed, or unextractable sources are not cached. The trace includes
per-source provenance and aggregate hit, miss, stale, invalid, and write counts.
Cache hits are rechecked against the current domain allowlist, including the
previously validated final redirect URL; changing policy cannot revive a source
that is no longer allowed.

## Inspection and maintenance

```bash
adversaryflow cache inspect
adversaryflow cache clear --kind nodes
adversaryflow cache clear --kind sources
adversaryflow cache clear --kind all --yes
adversaryflow storage status
adversaryflow storage migrate
adversaryflow storage list
adversaryflow storage verify RUN_ID
```

Clearing a cache never deletes completed runs. Cache deletion is safe because
entries are derived data, although the next generation may perform network and
model calls again.

## Migrations

The current store schema is version 2. Migrations are forward-only and registered
in `adversaryflow.storage.migrations`. Opening a `RunStore` automatically applies
pending migrations; operators can run them explicitly with `storage migrate`.

Version 0 represents a pre-versioned directory. The v0-to-v1 migration:

- adds `schema_version`, `status`, `artifacts`, and cache metadata to legacy manifests;
- preserves unknown manifest fields and every artifact;
- writes `store.json` with schema version 1;
- is idempotent.

The v1-to-v2 migration adds a `lineage` object to every manifest. Existing runs
become lineage roots. New adapted runs record `relationship: adaptation`, their
`parent_run_id`, request changes, predicted invalidations, and actual node reuse.
No existing request, report, trace, or scenario artifact is rewritten.

Before migrating a production store, make a filesystem snapshot or backup of the
store directory. A binary that encounters a newer store version stops rather
than attempting a downgrade. Test migrations against a copy before deploying a
new AdversaryFlow release across shared automation.

## Security and operations

- Treat the store as sensitive exercise data and restrict filesystem access.
- Do not place it in a synchronized or public directory without an explicit data policy.
- API keys and authorization headers are not persisted or included in cache keys.
- Source bodies are represented by normalized extracted documents, not raw HTTP responses.
- Do not share node caches between trust domains; validated model output can still contain scoped details.
- Back up `runs/` for audit retention. The `cache/` directory can be excluded from backups.
- Use one store per environment when retention or access policies differ.
