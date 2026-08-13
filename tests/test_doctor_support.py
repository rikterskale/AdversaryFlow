import zipfile
from pathlib import Path
from uuid import uuid4

from adversaryflow.doctor import run_doctor
from adversaryflow.support import create_support_bundle
from adversaryflow.platforms import SUPPORTED_PLATFORMS, detect_platform


def test_doctor_passes_repository_defaults():
    result = run_doctor()
    assert result["passed"] is True
    assert detect_platform() in SUPPORTED_PLATFORMS


def test_support_bundle_contains_redacted_diagnostics():
    bundle = create_support_bundle(Path("artifacts/test-support") / str(uuid4()))
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == {"diagnostics.json", "README.txt"}
        diagnostics = archive.read("diagnostics.json").decode().lower()
        assert "api_key" not in diagnostics
        assert "password" not in diagnostics
