import json
from pathlib import Path

from typer.testing import CliRunner

from adversaryflow.cli import app
from adversaryflow.storage.run_store import RunStore
from adversaryflow.storage.migrations import CURRENT_STORE_VERSION


runner = CliRunner()


def test_doctor_demo_requires_no_credentials() -> None:
    result = runner.invoke(app, ["doctor", "--demo"])

    assert result.exit_code == 0
    assert "Ready" in result.stdout


def test_generate_help_has_unambiguous_disable_flags() -> None:
    result = runner.invoke(app, ["generate", "--help"])

    assert result.exit_code == 0
    assert "--no-store" in result.stdout
    assert "--no-cache" in result.stdout
    assert "--no-no-store" not in result.stdout
    assert "--no-no-cache" not in result.stdout


def test_doctor_loads_dotenv_from_current_directory(tmp_path, monkeypatch) -> None:
    (tmp_path / ".env").write_text(
        "\n".join(
            (
                "ADVERSARYFLOW_LLM_BASE_URL=https://model.example/v1",
                "ADVERSARYFLOW_LLM_API_KEY=test-key",
                "ADVERSARYFLOW_LLM_MODEL=test-model",
                "ADVERSARYFLOW_SEARCH_PROVIDER=null",
            )
        ),
        encoding="utf-8",
    )
    for name in (
        "ADVERSARYFLOW_LLM_BASE_URL",
        "ADVERSARYFLOW_LLM_API_KEY",
        "ADVERSARYFLOW_LLM_MODEL",
        "ADVERSARYFLOW_SEARCH_PROVIDER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "test-model" in result.stdout


def test_validate_request_reports_invalid_json(tmp_path) -> None:
    request = tmp_path / "request.json"
    request.write_text('{"actor":', encoding="utf-8")

    result = runner.invoke(app, ["validate-request", "--request", str(request)])

    assert result.exit_code == 2
    assert "Invalid JSON at line 1" in result.stderr


def test_validate_request_accepts_minimal_tabletop(tmp_path) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "actor": "Example Actor",
                "objective": "Validate the incident response process.",
                "mode": "tabletop",
                "environment": {"name": "Example environment"},
                "roe": {},
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate-request", "--request", str(request)])

    assert result.exit_code == 0
    assert "Valid request" in result.stdout


def test_validate_request_accepts_utf8_bom_from_windows_powershell(tmp_path) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "actor": "Example Actor",
                "objective": "Validate the incident response process.",
                "mode": "tabletop",
                "environment": {"name": "Example environment"},
                "roe": {},
            }
        ),
        encoding="utf-8-sig",
    )

    result = runner.invoke(app, ["validate-request", "--request", str(request)])

    assert result.exit_code == 0


def test_live_generate_fails_with_actionable_configuration_error(tmp_path, monkeypatch) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "actor": "Example Actor",
                "objective": "Validate the incident response process.",
                "mode": "tabletop",
                "environment": {"name": "Example environment"},
                "roe": {},
            }
        ),
        encoding="utf-8",
    )
    for name in (
        "ADVERSARYFLOW_LLM_BASE_URL",
        "ADVERSARYFLOW_LLM_API_KEY",
        "ADVERSARYFLOW_LLM_MODEL",
        "ADVERSARYFLOW_BRAVE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    result = runner.invoke(app, ["generate", "--request", str(request)])

    assert result.exit_code == 2
    assert "Edit .env or run with --demo" in result.stderr


def test_generate_rejects_directory_as_output_before_model_calls(tmp_path) -> None:
    example = Path(__file__).parents[1] / "examples" / "tabletop_request.json"

    result = runner.invoke(
        app,
        ["generate", "--request", str(example), "--output", str(tmp_path), "--demo"],
    )

    assert result.exit_code == 2
    assert "Output path is not a file" in result.stderr


def test_init_creates_valid_safe_request(tmp_path) -> None:
    output = tmp_path / "starter.json"

    result = runner.invoke(
        app,
        [
            "init",
            "--output",
            str(output),
            "--actor",
            "Example Actor",
            "--objective",
            "Validate response procedures in a tabletop exercise.",
            "--environment",
            "Example Lab",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mode"] == "tabletop"
    assert payload["roe"]["no_destructive_execution"] is True


def test_export_schema_writes_scenario_request_schema(tmp_path) -> None:
    output = tmp_path / "request.schema.json"

    result = runner.invoke(app, ["export-schema", "--output", str(output)])

    assert result.exit_code == 0
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["title"] == "ScenarioRequest"
    assert "environment" in schema["properties"]


def test_generate_html_report(tmp_path) -> None:
    output = tmp_path / "scenario.html"
    store = tmp_path / "store"
    example = Path(__file__).parents[1] / "examples" / "apt29_request.json"

    result = runner.invoke(
        app,
        [
            "generate",
            "--request",
            str(example),
            "--output",
            str(output),
            "--store-dir",
            str(store),
            "--demo",
        ],
    )

    assert result.exit_code == 0
    html = output.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "<h1>APT29 Safe Red Team Exercise</h1>" in html
    assert (tmp_path / "scenario.trace.json").exists()
    run_dirs = list((store / "runs").iterdir())
    assert len(run_dirs) == 1
    manifest = json.loads((run_dirs[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == CURRENT_STORE_VERSION
    assert (run_dirs[0] / "scenario-pack.json").exists()
    assert (run_dirs[0] / "report.html").exists()
    persisted = RunStore(store)
    assert persisted.load_pack(manifest["run_id"]).title == "APT29 Safe Red Team Exercise"
    assert persisted.verify(manifest["run_id"]) == []
    assert persisted.list_runs()[0]["run_id"] == manifest["run_id"]


def test_second_demo_run_uses_node_cache(tmp_path) -> None:
    store = tmp_path / "store"
    example = Path(__file__).parents[1] / "examples" / "apt29_request.json"
    common = ["--request", str(example), "--store-dir", str(store), "--demo"]

    first = runner.invoke(app, ["generate", *common, "--output", str(tmp_path / "first.md")])
    second = runner.invoke(app, ["generate", *common, "--output", str(tmp_path / "second.md")])

    assert first.exit_code == 0
    assert second.exit_code == 0
    trace = json.loads((tmp_path / "second.trace.json").read_text(encoding="utf-8"))
    assert trace["cache"]["nodes"]["hits"] == 12
    assert trace["nodes"]["actor_identity"]["attempt_count"] == 0
