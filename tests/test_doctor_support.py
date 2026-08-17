import zipfile
from pathlib import Path
from uuid import uuid4

from adversaryflow.doctor import run_doctor
from adversaryflow.support import create_support_bundle
from adversaryflow.platforms import SUPPORTED_PLATFORMS, detect_platform


def test_doctor_passes_repository_defaults():
    result = run_doctor()
    assert result["passed"] is True
    assert result["adapter_readiness"]["compatible"] is True
    assert any(item["name"] == "execution-adapter" and item["passed"] for item in result["checks"])
    assert detect_platform() in SUPPORTED_PLATFORMS


def test_doctor_fix_creates_local_artifact_folders(monkeypatch):
    root = Path("artifacts") / f"doctor-fix-{uuid4()}"
    root.mkdir(parents=True)
    monkeypatch.chdir(root)
    result = run_doctor(fix=True)
    assert result["passed"] is True
    assert set(result["fixes_applied"]).issuperset({"artifacts", "artifacts/runs", "artifacts/campaigns", "artifacts/support"})
    assert run_doctor(fix=True)["fixes_applied"] == []


def test_doctor_reports_guided_fix_for_invalid_roe():
    invalid = Path("artifacts") / f"invalid-roe-{uuid4()}.yaml"
    invalid.write_text("engagement_name: missing-required-fields\n", encoding="utf-8")
    result = run_doctor(str(invalid))
    assert result["passed"] is False
    assert any(item["check"] == "roe" and item["fix"] for item in result["guided_fixes"])


def test_doctor_uses_a_safe_version_fallback_when_package_metadata_is_unavailable(monkeypatch):
    import adversaryflow.doctor as doctor

    monkeypatch.setattr(doctor, "package_version", lambda _name: (_ for _ in ()).throw(doctor.PackageNotFoundError()))
    assert run_doctor()["version"] == "0.2.3"


def test_support_bundle_contains_redacted_diagnostics():
    bundle = create_support_bundle(Path("artifacts/test-support") / str(uuid4()))
    with zipfile.ZipFile(bundle) as archive:
        assert set(archive.namelist()) == {"diagnostics.json", "README.txt"}
        diagnostics = archive.read("diagnostics.json").decode().lower()
        assert "api_key" not in diagnostics
        assert "password" not in diagnostics
