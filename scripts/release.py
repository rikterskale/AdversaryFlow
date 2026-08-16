"""Build and verify AdversaryFlow release artifacts."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from adversaryflow.catalog import CATALOG_MANIFEST_FORMAT, catalog_release_record


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_release(output: str | Path = "artifacts/release") -> Path:
    destination = (ROOT / output).resolve() if not Path(output).is_absolute() else Path(output).resolve()
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    dist = ROOT / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(destination)], cwd=ROOT, check=True)
    zip_path = destination / "adversaryflow-source.zip"
    excluded = {".git", ".venv", "dist", "artifacts", "__pycache__", ".pytest_cache", ".pytest-local"}
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.relative_to(ROOT).parts):
                continue
            archive.write(path, Path("adversaryflow") / path.relative_to(ROOT))
    catalog_dir = ROOT / "content" / "abilities"
    catalog_records = []
    for path in sorted(catalog_dir.glob("*.json")):
        record = catalog_release_record(path)
        record["path"] = path.relative_to(ROOT).as_posix()
        catalog_records.append(record)
    (destination / "catalog-manifest.json").write_text(json.dumps({"format": CATALOG_MANIFEST_FORMAT, "catalogs": catalog_records}, indent=2), encoding="utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "adversaryflow", "version": project_version()}}, "components": [{"type": "library", "name": "PyYAML", "version": ">=6.0"}, {"type": "library", "name": "pytest", "version": ">=8.0", "scope": "development"}]}
    (destination / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    artifacts = sorted(path for path in destination.iterdir() if path.is_file())
    manifest = {"format": "ADVERSARYFLOW-RELEASE-MANIFEST-1", "created_at": datetime.now(timezone.utc).isoformat(), "catalog_manifest": "catalog-manifest.json", "sbom": "sbom.cdx.json", "artifacts": [{"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size} for path in artifacts]}
    (destination / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    signing_key = os.environ.get("ADVERSARYFLOW_RELEASE_GPG_KEY")
    if signing_key:
        sign_release(destination, signing_key)
    return destination


def sign_release(release_dir: str | Path, key: str) -> Path:
    """Create an armored detached GPG signature for the release manifest."""
    root = Path(release_dir)
    signature = root / "SHA256SUMS.json.asc"
    subprocess.run(["gpg", "--batch", "--yes", "--armor", "--detach-sign", "--local-user", key, "--output", str(signature), str(root / "SHA256SUMS.json")], check=True)
    return signature


def verify_release_signature(release_dir: str | Path, keyring: str | Path | None = None) -> bool:
    root = Path(release_dir)
    command = ["gpg", "--batch", "--verify", str(root / "SHA256SUMS.json.asc"), str(root / "SHA256SUMS.json")]
    if keyring:
        command[1:1] = ["--no-default-keyring", "--keyring", str(keyring)]
    return subprocess.run(command, capture_output=True).returncode == 0


def verify_release(release_dir: str | Path) -> bool:
    root = Path(release_dir)
    manifest = json.loads((root / "SHA256SUMS.json").read_text(encoding="utf-8"))
    if manifest.get("format") != "ADVERSARYFLOW-RELEASE-MANIFEST-1":
        return False
    try:
        items = manifest.get("artifacts")
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            return False
        names = [item.get("name") for item in items]
        if not names or len(names) != len(set(names)):
            return False
        if manifest.get("catalog_manifest") not in names or manifest.get("sbom") not in names:
            return False
        def release_file(name: str) -> Path | None:
            if not isinstance(name, str):
                return None
            path = (root / name).resolve()
            return path if path.parent == root.resolve() and path.exists() else None

        catalog_path = release_file(manifest["catalog_manifest"])
        sbom_path = release_file(manifest["sbom"])
        if catalog_path is None or sbom_path is None:
            return False
        if "catalog_manifest" in manifest:
            catalog_manifest = json.loads(catalog_path.read_text(encoding="utf-8"))
            if catalog_manifest.get("format") != CATALOG_MANIFEST_FORMAT or not catalog_manifest.get("catalogs"):
                return False
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        if sbom.get("bomFormat") != "CycloneDX" or sbom.get("metadata", {}).get("component", {}).get("name") != "adversaryflow":
            return False
        return all(
            isinstance(item.get("name"), str)
            and (root / item["name"]).resolve().parent == root.resolve()
            and (root / item["name"]).exists()
            and sha256(root / item["name"]) == item["sha256"]
            and (root / item["name"]).stat().st_size == item["bytes"]
            for item in items
        )
    except (KeyError, OSError, ValueError, TypeError):
        return False


if __name__ == "__main__":
    destination = build_release(sys.argv[1] if len(sys.argv) > 1 else "artifacts/release")
    result = {"release_dir": str(destination), "verified": verify_release(destination)}
    if (destination / "SHA256SUMS.json.asc").exists():
        result["signature"] = str(destination / "SHA256SUMS.json.asc")
    print(json.dumps(result, indent=2))
