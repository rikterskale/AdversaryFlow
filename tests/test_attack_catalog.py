from pathlib import Path

from adversaryflow.retrieval.attack_catalog import AttackCatalog


def test_resolve_group_and_uses() -> None:
    fixture = Path(__file__).parent / "fixtures" / "mini-attack.json"
    catalog = AttackCatalog(fixture)
    group = catalog.resolve_group("EA")
    assert group is not None
    assert catalog.external_id(group) == "G9999"
    relationships = catalog.uses(group["id"])
    assert relationships["techniques"][0]["external_id"] == "T9999"
