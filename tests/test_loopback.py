import hashlib
import json

import pytest

from adversaryflow.loopback import LoopbackSink
from adversaryflow.manager import _release_status


def test_loopback_sink_accepts_only_local_synthetic_marker():
    with LoopbackSink() as sink:
        sink.send_marker("run-test")
        assert sink.url.startswith("http://127.0.0.1:")
        assert sink.received[0]["path"] == "/beacon"
        assert "ADVERSARYFLOW_SYNTHETIC" in sink.received[0]["body"]


def test_loopback_sink_refuses_a_non_success_response(monkeypatch):
    class Response:
        status = 500
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    monkeypatch.setattr("adversaryflow.loopback.urlopen", lambda *_args, **_kwargs: Response())
    with LoopbackSink() as sink:
        with pytest.raises(RuntimeError, match="rejected synthetic marker"):
            sink.send_marker("run-test")


def test_release_status_explains_missing_local_inventory(tmp_path):
    result = _release_status(tmp_path / "release")
    assert result["available"] is False
    assert "release.py" in result["next"]


def test_release_status_verifies_inventory_and_signature_marker(tmp_path):
    root = tmp_path / "release"
    root.mkdir()
    catalog = root / "catalog-manifest.json"
    catalog.write_text("{}", encoding="utf-8")
    sbom = root / "sbom.cdx.json"
    sbom.write_text("{}", encoding="utf-8")
    entries = [{"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size} for path in (catalog, sbom)]
    (root / "SHA256SUMS.json").write_text(json.dumps({"artifacts": entries, "catalog_manifest": catalog.name, "sbom": sbom.name}), encoding="utf-8")
    (root / "SHA256SUMS.json.asc").write_text("signature", encoding="utf-8")
    result = _release_status(root)
    assert result["available"] is True
    assert result["verified"] is True
    assert result["signature"] is True
