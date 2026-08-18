from pathlib import Path
from uuid import uuid4

from scripts.artifact_journey import isolated_environment, journey
from scripts.release_readiness import validate_documentation


def test_artifact_journey_requires_release_artifacts():
    tmp_path = Path("artifacts/test-journey") / str(uuid4())
    tmp_path.mkdir(parents=True)
    try:
        journey(tmp_path)
    except FileNotFoundError as exc:
        assert "No release artifacts" in str(exc)
    else:
        raise AssertionError("journey should require release artifacts")


def test_release_readiness_documentation_is_complete():
    validate_documentation()


def test_artifact_journey_removes_source_import_overrides(monkeypatch):
    monkeypatch.setenv("PYTHONHOME", "source-home")
    monkeypatch.setenv("PYTHONPATH", "source-path")
    environment = isolated_environment({"ADVERSARYFLOW_PROVIDER": "offline"})
    assert "PYTHONHOME" not in environment
    assert "PYTHONPATH" not in environment
    assert environment["ADVERSARYFLOW_PROVIDER"] == "offline"
