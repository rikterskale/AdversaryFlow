import json
from pathlib import Path

import pytest

from adversaryflow.catalog import catalog_release_record, validate_catalog_document
from adversaryflow.emulation import load_catalog


def test_shipped_catalogs_have_governance_metadata_and_unique_abilities():
    for path in sorted(Path("content/abilities").glob("*.json")):
        record = catalog_release_record(path)
        assert record["status"] == "active"
        assert record["version"] == "1.0.0"
        assert record["ability_ids"]
        assert len(record["ability_ids"]) == len(set(record["ability_ids"]))


def test_loader_rejects_catalog_without_governance(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps({"format": "ADVERSARYFLOW-ABILITY-CATALOG-1", "abilities": [{"id": "a"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="governance"):
        load_catalog(path)


def test_loader_rejects_deprecated_catalog_ability(tmp_path):
    raw = json.loads(Path("content/abilities/catalog.json").read_text(encoding="utf-8"))
    raw["abilities"][0]["lifecycle"] = {"status": "deprecated", "replacement_id": raw["abilities"][1]["id"], "reason": "superseded"}
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="deprecated"):
        load_catalog(path)


def test_catalog_document_rejects_duplicate_ids():
    raw = json.loads(Path("content/abilities/catalog.json").read_text(encoding="utf-8"))
    raw["abilities"].append(dict(raw["abilities"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        validate_catalog_document(raw)
