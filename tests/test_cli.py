import json

from typer.testing import CliRunner

from adversaryflow.cli import app


runner = CliRunner()


def test_doctor_demo_requires_no_credentials() -> None:
    result = runner.invoke(app, ["doctor", "--demo"])

    assert result.exit_code == 0
    assert "Ready" in result.stdout


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
