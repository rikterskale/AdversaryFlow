import json
from datetime import datetime, timezone

import pytest

from adversaryflow.models import SourceDocument, SourceRecord, SourceTier
from adversaryflow.pipeline.node_runner import NodeRunner
from adversaryflow.providers.demo import DemoLLMProvider
from adversaryflow.storage.cache import NodeCache, SourceCache, cache_inventory, clear_cache
from adversaryflow.storage.migrations import CURRENT_STORE_VERSION, migrate_store, store_version


async def test_node_cache_reuses_validated_output(tmp_path) -> None:
    cache = NodeCache(tmp_path)
    first_provider = DemoLLMProvider()
    first = NodeRunner(
        llm=first_provider,
        cache=cache,
        provider_identity=first_provider.cache_identity,
    )
    payload = {"actor": "APT29", "request": {"actor": "APT29"}}

    original = await first.run("actor_identity", payload)
    second_provider = DemoLLMProvider()
    second = NodeRunner(
        llm=second_provider,
        cache=NodeCache(tmp_path),
        provider_identity=second_provider.cache_identity,
    )
    cached = await second.run("actor_identity", payload)

    assert cached == original
    assert first_provider.call_count == 1
    assert second_provider.call_count == 0
    assert second.trace["actor_identity"]["cache"]["status"] == "hit"


async def test_node_cache_key_changes_with_inputs(tmp_path) -> None:
    cache = NodeCache(tmp_path)
    provider = DemoLLMProvider()
    runner = NodeRunner(llm=provider, cache=cache, provider_identity=provider.cache_identity)

    await runner.run("actor_identity", {"actor": "APT29"})
    await runner.run("actor_identity", {"actor": "APT28"})

    assert provider.call_count == 2
    assert cache.stats.misses == 2


def test_source_cache_is_content_addressed_and_freshness_aware(tmp_path) -> None:
    record = SourceRecord(
        url="https://attack.mitre.org/groups/G0016/",
        final_url="https://attack.mitre.org/groups/G0016/",
        title="APT29",
        domain="attack.mitre.org",
        tier=SourceTier.AUTHORITATIVE,
        validated=True,
        content_sha256="a" * 64,
    )
    document = SourceDocument(source=record, text="Grounded content", chunks=[])
    cache = SourceCache(tmp_path, ttl_seconds=3600)

    cache.put(document)
    loaded = cache.get(record)

    assert loaded == document
    assert cache.stats.hits == 1
    document_files = list((tmp_path / "cache" / "sources" / "documents").rglob("*.json"))
    assert document_files[0].stem == "a" * 64

    assert cache.get(record, accept=lambda _: False) is None
    assert cache.stats.invalid == 1

    stale_cache = SourceCache(tmp_path, ttl_seconds=0)
    assert stale_cache.get(record) is None
    assert stale_cache.stats.stale == 1


def test_cache_inventory_and_selective_clear(tmp_path) -> None:
    node_path = tmp_path / "cache" / "nodes" / "aa" / "entry.json"
    source_path = tmp_path / "cache" / "sources" / "urls" / "bb" / "entry.json"
    node_path.parent.mkdir(parents=True)
    source_path.parent.mkdir(parents=True)
    node_path.write_text("{}", encoding="utf-8")
    source_path.write_text("{}", encoding="utf-8")

    assert cache_inventory(tmp_path)["nodes"]["files"] == 1
    clear_cache(tmp_path, "nodes")

    assert not node_path.exists()
    assert source_path.exists()


def test_migration_upgrades_legacy_manifest(tmp_path) -> None:
    manifest_path = tmp_path / "runs" / "legacy-run" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(
        json.dumps(
            {
                "run_id": "legacy-run",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "request_sha256": "a" * 64,
            }
        ),
        encoding="utf-8",
    )

    applied = migrate_store(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert applied == ["v0->v1", "v1->v2"]
    assert store_version(tmp_path) == CURRENT_STORE_VERSION
    assert manifest["schema_version"] == CURRENT_STORE_VERSION
    assert manifest["status"] == "completed"
    assert manifest["lineage"] == {"relationship": "root", "parent_run_id": None}
    assert migrate_store(tmp_path) == []


def test_migration_rejects_newer_store(tmp_path) -> None:
    (tmp_path / "store.json").write_text('{"schema_version": 999}', encoding="utf-8")

    with pytest.raises(ValueError, match="newer than supported"):
        migrate_store(tmp_path)


def test_v1_migration_adds_root_lineage_without_changing_artifacts(tmp_path) -> None:
    run_dir = tmp_path / "runs" / "existing"
    run_dir.mkdir(parents=True)
    artifact = run_dir / "report.md"
    artifact.write_text("preserve me", encoding="utf-8")
    (run_dir / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "run_id": "existing", "artifacts": {}}),
        encoding="utf-8",
    )
    (tmp_path / "store.json").write_text('{"schema_version": 1}', encoding="utf-8")

    assert migrate_store(tmp_path) == ["v1->v2"]
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["lineage"] == {"relationship": "root", "parent_run_id": None}
    assert artifact.read_text(encoding="utf-8") == "preserve me"
