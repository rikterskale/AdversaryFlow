import json
from pathlib import Path
from zipfile import ZipFile

from typer.testing import CliRunner

from adversaryflow.cli import app
from adversaryflow.models import ScenarioRequest
from adversaryflow.pipeline.dependencies import Dependency, changed_dependencies, invalidated_nodes


runner = CliRunner()
ROOT = Path(__file__).parents[1]


def _request() -> ScenarioRequest:
    return ScenarioRequest.model_validate_json(
        (ROOT / "examples" / "apt29_request.json").read_text(encoding="utf-8")
    )


def test_dependency_metadata_limits_environment_invalidation() -> None:
    before = _request()
    payload = before.model_dump(mode="json")
    payload["environment"]["security_tools"].append("Network Detection")
    after = ScenarioRequest.model_validate(payload)

    changed = changed_dependencies(before, after)
    invalid = invalidated_nodes(changed)

    assert changed == frozenset({Dependency.ENVIRONMENT})
    assert "actor_identity" not in invalid
    assert "dossier_synthesis" not in invalid
    assert "environment_fit" in invalid
    assert "telemetry_mapping" in invalid
    assert "final_composition" in invalid


def test_adapt_reuses_unaffected_nodes_and_records_lineage(tmp_path) -> None:
    store = tmp_path / "store"
    parent_output = tmp_path / "parent.md"
    source_request = ROOT / "examples" / "apt29_request.json"
    first = runner.invoke(
        app,
        [
            "generate",
            "--request",
            str(source_request),
            "--output",
            str(parent_output),
            "--store-dir",
            str(store),
            "--demo",
        ],
    )
    assert first.exit_code == 0
    parent_manifest = json.loads(
        next((store / "runs").glob("*/manifest.json")).read_text(encoding="utf-8")
    )
    parent_id = parent_manifest["run_id"]
    environment = _request().environment.model_dump(mode="json")
    environment["security_tools"].append("Network Detection")
    environment_path = tmp_path / "environment.json"
    environment_path.write_text(json.dumps(environment), encoding="utf-8")

    adapted_output = tmp_path / "adapted.html"
    result = runner.invoke(
        app,
        [
            "adapt",
            "--from",
            parent_id,
            "--environment",
            str(environment_path),
            "--output",
            str(adapted_output),
            "--store-dir",
            str(store),
            "--demo",
        ],
    )

    assert result.exit_code == 0, result.output
    manifests = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (store / "runs").glob("*/manifest.json")
    ]
    child = next(item for item in manifests if item["run_id"] != parent_id)
    assert child["lineage"] == {"relationship": "adaptation", "parent_run_id": parent_id}
    assert child["adaptation"]["changed_dependencies"] == ["environment"]
    assert "actor_identity" in child["adaptation"]["actual_reused_nodes"]
    assert "dossier_synthesis" in child["adaptation"]["actual_reused_nodes"]
    assert "environment_fit" in child["adaptation"]["actual_executed_nodes"]
    assert adapted_output.exists()


def test_diff_and_operator_pack_exports(tmp_path) -> None:
    store = tmp_path / "store"
    source_request = ROOT / "examples" / "apt29_request.json"
    runner.invoke(
        app,
        [
            "generate",
            "--request",
            str(source_request),
            "--output",
            str(tmp_path / "first.md"),
            "--store-dir",
            str(store),
            "--demo",
        ],
    )
    parent = json.loads(next((store / "runs").glob("*/manifest.json")).read_text(encoding="utf-8"))[
        "run_id"
    ]
    changed_request = _request().model_dump(mode="json")
    changed_request["objective"] = "Validate adapted identity and endpoint response procedures."
    request_path = tmp_path / "changed.json"
    request_path.write_text(json.dumps(changed_request), encoding="utf-8")
    runner.invoke(
        app,
        [
            "adapt",
            "--from",
            parent,
            "--request",
            str(request_path),
            "--output",
            str(tmp_path / "second.md"),
            "--store-dir",
            str(store),
            "--demo",
        ],
    )
    manifests = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (store / "runs").glob("*/manifest.json")
    ]
    child = next(item["run_id"] for item in manifests if item["run_id"] != parent)

    diff_path = tmp_path / "diff.json"
    diff_result = runner.invoke(
        app,
        [
            "diff",
            parent,
            child,
            "--store-dir",
            str(store),
            "--format",
            "json",
            "--output",
            str(diff_path),
        ],
    )
    assert diff_result.exit_code == 0
    difference = json.loads(diff_path.read_text(encoding="utf-8"))
    assert "objective" in difference["changed_dependencies"]
    assert any(item["path"] == "objective" for item in difference["request_changes"])

    operator_zip = tmp_path / "operator.zip"
    export_result = runner.invoke(
        app,
        [
            "export",
            "operator",
            child,
            "--store-dir",
            str(store),
            "--output",
            str(operator_zip),
            "--zip",
        ],
    )
    assert export_result.exit_code == 0
    with ZipFile(operator_zip) as archive:
        names = set(archive.namelist())
        assert "01_Operator_Injects.md" in names
        assert "03_Expected_Telemetry.md" in names
        assert "full_report.html" in names
        assert "operator_manifest.json" in names
