import json
from pathlib import Path
from uuid import uuid4

from scripts.release import sha256, verify_release


def test_release_verifier_accepts_matching_manifest():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    artifact = tmp_path / "example.txt"
    artifact.write_text("release", encoding="utf-8")
    manifest = {"format": "ADVERSARYFLOW-RELEASE-MANIFEST-1", "artifacts": [{"name": artifact.name, "sha256": sha256(artifact), "bytes": artifact.stat().st_size}]}
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert verify_release(tmp_path) is True


def test_release_verifier_rejects_tampering():
    tmp_path = Path("artifacts/test-release") / str(uuid4())
    tmp_path.mkdir(parents=True)
    artifact = tmp_path / "example.txt"
    artifact.write_text("release", encoding="utf-8")
    manifest = {"format": "ADVERSARYFLOW-RELEASE-MANIFEST-1", "artifacts": [{"name": artifact.name, "sha256": sha256(artifact), "bytes": artifact.stat().st_size}]}
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest), encoding="utf-8")
    artifact.write_text("tampered", encoding="utf-8")
    assert verify_release(tmp_path) is False
