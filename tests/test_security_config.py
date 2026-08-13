import json
from pathlib import Path


def test_sbom_schema_has_required_identity():
    path = Path("artifacts/release/sbom.cdx.json")
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["metadata"]["component"]["name"] == "adversaryflow"
