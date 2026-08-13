"""Build and verify AdversaryFlow release artifacts."""

import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
    excluded = {".git", ".venv", "dist", "artifacts", "__pycache__", ".pytest_cache"}
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in ROOT.rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.relative_to(ROOT).parts):
                continue
            archive.write(path, Path("adversaryflow") / path.relative_to(ROOT))
    artifacts = sorted(path for path in destination.iterdir() if path.is_file())
    manifest = {"format": "ADVERSARYFLOW-RELEASE-MANIFEST-1", "created_at": datetime.now(timezone.utc).isoformat(), "artifacts": [{"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size} for path in artifacts]}
    (destination / "SHA256SUMS.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"component": {"type": "application", "name": "adversaryflow", "version": "0.1.0"}}, "components": [{"type": "library", "name": "PyYAML", "version": ">=6.0"}, {"type": "library", "name": "pytest", "version": ">=8.0", "scope": "development"}]}
    (destination / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return destination


def verify_release(release_dir: str | Path) -> bool:
    root = Path(release_dir)
    manifest = json.loads((root / "SHA256SUMS.json").read_text(encoding="utf-8"))
    return all((root / item["name"]).exists() and sha256(root / item["name"]) == item["sha256"] for item in manifest["artifacts"])


if __name__ == "__main__":
    destination = build_release(sys.argv[1] if len(sys.argv) > 1 else "artifacts/release")
    print(json.dumps({"release_dir": str(destination), "verified": verify_release(destination)}, indent=2))

