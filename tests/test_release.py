import json
from pathlib import Path
from uuid import uuid4

from scripts.release import sha256, verify_release


def _release_metadata(tmp_path: Path) -> tuple[Path, Path]:
    catalog = tmp_path / "catalog-manifest.json"
    catalog.write_text(json.dumps({"format": "ADVERSARYFLOW-CATALOG-MANIFEST-1", "catalogs": [{"name": "core", "version": "1.0.0", "status": "active"}]}), encoding="utf-8")
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "adversaryflow"}}}), encoding="utf-8")
    return catalog, sbom


def _manifest(artifact: Path, catalog: Path, sbom: Path) -> dict:
    return {
        "format": "ADVERSARYFLOW-RELEASE-MANIFEST-1",
        "catalog_manifest": catalog.name,
        "sbom": sbom.name,
        "artifacts": [
            {"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
            for path in (artifact, catalog, sbom)
        ],
    }


def test_release_verifier_accepts_matching_manifest():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    artifact = tmp_path / "example.txt"
    artifact.write_text("release", encoding="utf-8")
    catalog, sbom = _release_metadata(tmp_path)
    manifest = _manifest(artifact, catalog, sbom)
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_release(tmp_path) is True


def test_release_verifier_rejects_tampering():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    artifact = tmp_path / "example.txt"
    artifact.write_text("release", encoding="utf-8")
    catalog, sbom = _release_metadata(tmp_path)
    manifest = _manifest(artifact, catalog, sbom)
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text("tampered", encoding="utf-8")
    assert verify_release(tmp_path) is False


def test_release_verifier_accepts_catalog_manifest_when_checksumed():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    artifact = tmp_path / "example.txt"
    artifact.write_text("release", encoding="utf-8")
    catalog_manifest = tmp_path / "catalog-manifest.json"
    catalog_manifest.write_text(json.dumps({"format": "ADVERSARYFLOW-CATALOG-MANIFEST-1", "catalogs": [{"name": "core", "version": "1.0.0", "status": "active"}]}), encoding="utf-8")
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "adversaryflow"}}}), encoding="utf-8")
    manifest = {
        "format": "ADVERSARYFLOW-RELEASE-MANIFEST-1",
        "catalog_manifest": catalog_manifest.name,
        "sbom": sbom.name,
        "artifacts": [
            {"name": artifact.name, "sha256": sha256(artifact), "bytes": artifact.stat().st_size},
            {"name": catalog_manifest.name, "sha256": sha256(catalog_manifest), "bytes": catalog_manifest.stat().st_size},
            {"name": sbom.name, "sha256": sha256(sbom), "bytes": sbom.stat().st_size},
        ],
    }
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_release(tmp_path) is True


def test_release_verifier_requires_catalog_and_sbom_inventory_entries():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    catalog_manifest = tmp_path / "catalog-manifest.json"
    catalog_manifest.write_text(json.dumps({"format": "ADVERSARYFLOW-CATALOG-MANIFEST-1", "catalogs": [{"name": "core", "version": "1.0.0", "status": "active"}]}), encoding="utf-8")
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"name": "adversaryflow"}}}), encoding="utf-8")
    manifest = {
        "format": "ADVERSARYFLOW-RELEASE-MANIFEST-1",
        "catalog_manifest": catalog_manifest.name,
        "sbom": sbom.name,
        "artifacts": [{"name": catalog_manifest.name, "sha256": sha256(catalog_manifest), "bytes": catalog_manifest.stat().st_size}],
    }
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_release(tmp_path) is False
