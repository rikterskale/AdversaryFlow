import json
from pathlib import Path

import pytest

from adversaryflow.catalog import canonical_json, catalog_release_record, load_catalog_document, validate_catalog_document
from adversaryflow.emulation import Ability, load_catalog


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


def _minimal_catalog():
    return {"format": "ADVERSARYFLOW-ABILITY-CATALOG-1", "governance": {"name": "test", "version": "1.0.0", "status": "active"}, "abilities": [{"id": "ability-one"}]}


@pytest.mark.parametrize(("change", "message"), [
    ({"format": "wrong"}, "must use"),
    ({"abilities": []}, "non-empty"),
    ({"governance": {"name": "", "version": "1.0.0", "status": "active"}}, "non-empty string"),
    ({"governance": {"name": "test", "version": "1", "status": "active"}}, "semantic"),
    ({"governance": {"name": "test", "version": "1.0.0", "status": "unknown"}}, "must be active"),
    ({"governance": {"name": "test", "version": "1.0.0", "status": "deprecated"}}, "catalog is deprecated"),
    ({"abilities": ["not-an-object"]}, "non-object"),
    ({"abilities": [{"id": ""}]}, "non-empty strings"),
    ({"abilities": [{"id": "ability-one", "lifecycle": "bad"}]}, "invalid lifecycle"),
    ({"abilities": [{"id": "ability-one", "lifecycle": {"status": "retired"}}]}, "deprecated or retired"),
])
def test_catalog_governance_rejects_invalid_documents(change, message):
    raw = _minimal_catalog()
    raw.update(change)
    with pytest.raises(ValueError, match=message):
        validate_catalog_document(raw)


def test_legacy_validation_and_canonical_hash_helpers(tmp_path):
    raw = _minimal_catalog(); raw.pop("governance")
    assert validate_catalog_document(raw)["status"] == "active"
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded, governance = load_catalog_document(path, require_governance=False)
    assert loaded["format"] == "ADVERSARYFLOW-ABILITY-CATALOG-1"
    assert governance["name"] == "catalog"
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_ability_rejects_non_active_lifecycle_directly():
    raw = json.loads(Path("content/abilities/catalog.json").read_text(encoding="utf-8"))["abilities"][0]
    raw["lifecycle"] = {"status": "retired"}
    with pytest.raises(ValueError, match="retired"):
        Ability.from_mapping(raw)
