"""Coverage for the CLI UX enhancements: output modes, colour, exit codes,
shell completion, and the exit-code explainer. All checks stay offline and
never contact a target."""

import io
import json
import os
import subprocess
import sys

import pytest

from adversaryflow import output
from adversaryflow.completion import SUPPORTED_SHELLS, completion_script
from adversaryflow.output import EXIT_CODE_HELP, ExitCode, resolve_mode, respond, severity, supports_color


class _Args:
    def __init__(self, **kwargs):
        self.json = kwargs.get("json", False)
        self.human = kwargs.get("human", False)
        self.quiet = kwargs.get("quiet", False)
        self.verbose = kwargs.get("verbose", False)
        self.no_color = kwargs.get("no_color", False)


def test_supports_color_respects_no_color_and_force(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert supports_color(no_color=True) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color() is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color() is True


def test_resolve_mode_prefers_explicit_flags_then_tty(monkeypatch):
    assert resolve_mode(_Args(json=True)) == output.JSON
    assert resolve_mode(_Args(quiet=True)) == output.QUIET
    assert resolve_mode(_Args(human=True)) == output.HUMAN
    # No flags and a non-tty stdout resolves to JSON (deterministic for scripts).
    monkeypatch.setattr(output.sys, "stdout", io.StringIO())
    assert resolve_mode(_Args()) == output.JSON


def test_respond_json_mode_emits_pretty_json(capsys):
    respond(_Args(json=True), {"a": 1, "b": [2, 3]})
    assert json.loads(capsys.readouterr().out) == {"a": 1, "b": [2, 3]}


def test_respond_human_mode_uses_supplied_text(capsys):
    respond(_Args(human=True), {"status": "ok"}, human="all good")
    assert capsys.readouterr().out.strip() == "all good"


def test_respond_quiet_mode_prints_terse_line(capsys):
    respond(_Args(quiet=True), {"success": False, "error": "boom"})
    assert capsys.readouterr().out.strip() == "error: boom"
    respond(_Args(quiet=True), {"stage": "drafted", "campaign_id": "c-1"})
    assert capsys.readouterr().out.strip() == "drafted"


def test_respond_exit_code_raises_for_nonzero(capsys):
    with pytest.raises(SystemExit) as exit_info:
        respond(_Args(json=True), {"error": "nope"}, exit_code=ExitCode.ERROR)
    assert exit_info.value.code == ExitCode.ERROR


def test_severity_is_plain_when_colour_disabled():
    line = severity("PASS", "everything fine", "ok", enabled=False)
    assert line == "PASS everything fine"
    coloured = severity("FAIL", "broken", "fail", enabled=True)
    assert "FAIL" in coloured and coloured != "FAIL broken"


def test_every_exit_code_has_help_text():
    codes = {value for name, value in vars(ExitCode).items() if name.isupper()}
    assert codes == set(EXIT_CODE_HELP)
    assert EXIT_CODE_HELP[ExitCode.OK].startswith("Success")


@pytest.mark.parametrize("shell", SUPPORTED_SHELLS)
def test_completion_script_mentions_core_commands(shell):
    script = completion_script(shell)
    assert "adversaryflow" in script
    assert "campaign" in script and "doctor" in script


def test_completion_rejects_unknown_shell():
    with pytest.raises(ValueError):
        completion_script("tcsh")


def _cli(*args, **env_extra):
    env = {**os.environ, "PYTHONPATH": "src", **env_extra}
    return subprocess.run([sys.executable, "-m", "adversaryflow", *args], capture_output=True, text=True, env=env)


def test_cli_completion_command_emits_script():
    result = _cli("completion", "bash")
    assert result.returncode == 0
    assert "_adversaryflow" in result.stdout


def test_cli_explain_single_code_is_json():
    result = _cli("explain", "3")
    payload = json.loads(result.stdout)
    assert payload["code"] == 3
    assert "Scope violation" in payload["meaning"]


def test_cli_explain_lists_all_codes():
    payload = json.loads(_cli("explain").stdout)
    codes = {entry["code"] for entry in payload["exit_codes"]}
    assert {0, 1, 2}.issubset(codes)


def test_cli_quiet_flag_suppresses_full_payload():
    result = _cli("validate", "examples/roe.yaml", "--quiet")
    # Quiet mode prints no JSON braces, just a short status-derived line or nothing.
    assert "{" not in result.stdout


def test_cli_json_flag_forces_machine_output():
    result = _cli("validate", "examples/roe.yaml", "--json")
    assert json.loads(result.stdout)["valid"] is True


def test_cli_adapter_status_is_json_by_default_when_piped():
    result = _cli("adapter", "status")
    assert json.loads(result.stdout)["adapter"] == "local-synthetic"


# --- Direct coverage for output.py helpers ---

def test_supports_color_handles_stream_without_isatty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class Boom:
        def isatty(self):
            raise RuntimeError("no tty here")

    assert supports_color(Boom()) is False


def test_enable_windows_vt_is_safe_to_call():
    # No-op off Windows; wrapped in try/except on Windows. Must never raise.
    output._enable_windows_vt()


def test_colorize_returns_plain_when_disabled_or_unknown():
    assert output.colorize("x", "green", enabled=False) == "x"
    assert output.colorize("x", "not-a-colour", enabled=True) == "x"
    assert output.colorize("x", "green", enabled=True) != "x"


def test_severity_default_enabled_follows_force_color(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    line = severity("PASS", "ok", "ok")
    assert "PASS" in line and line != "PASS ok"


def test_resolve_mode_defaults_to_human_on_colour_terminal(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert resolve_mode(_Args()) == output.HUMAN


def test_quiet_line_covers_success_and_empty(capsys):
    respond(_Args(quiet=True), {"success": True})
    assert capsys.readouterr().out.strip() == "ok"
    respond(_Args(quiet=True), {"success": False})
    assert capsys.readouterr().out.strip() == "failed"
    respond(_Args(quiet=True), {"unrelated": 1})
    assert capsys.readouterr().out == ""


def test_progress_writes_only_on_colour_stream(monkeypatch):
    monkeypatch.setenv("FORCE_COLOR", "1")
    buf = io.StringIO()
    output.progress("fetching", 1, 3, stream=buf)
    output.progress("no counter", stream=buf)
    assert "fetching" in buf.getvalue() and "no counter" in buf.getvalue()
    monkeypatch.delenv("FORCE_COLOR")
    quiet = io.StringIO()
    output.progress("hidden", stream=quiet)
    assert quiet.getvalue() == ""


def test_dry_run_banner_renders_when_enabled():
    buf = io.StringIO()
    output.dry_run_banner(["draft a plan"], ["contact a target"], enabled=True, stream=buf)
    text = buf.getvalue()
    assert "DRY RUN" in text and "draft a plan" in text and "contact a target" in text
    off = io.StringIO()
    output.dry_run_banner(["x"], ["y"], enabled=False, stream=off)
    assert off.getvalue() == ""


# --- Direct coverage for cli.py human helpers and the interactive picker ---

def test_campaign_table_handles_empty_and_populated():
    from adversaryflow import cli

    assert "No saved campaigns" in cli._campaign_table([], enabled=False)
    table = cli._campaign_table([{"campaign_id": "c-1", "status": "completed"}], enabled=False)
    assert "c-1" in table and "completed" in table and "CAMPAIGN" in table


def test_campaign_result_human_covers_each_stage():
    from adversaryflow import cli

    assert "COMPLETED" in cli._campaign_result_human({"campaign_id": "c-1", "run_dir": "runs/x"}, enabled=False)
    assert "DRAFTED" in cli._campaign_result_human({"campaign_id": "c-1", "stage": "drafted", "provider": "offline"}, enabled=False)
    assert "REJECTED" in cli._campaign_result_human({"campaign_id": "c-1", "stage": "rejected"}, enabled=False)


def test_doctor_human_includes_remediation_plan_when_failing():
    from adversaryflow import cli

    failing = {
        "passed": False,
        "platform": "Windows-11",
        "checks": [{"passed": False, "name": "roe", "detail": "missing"}],
        "fixes_applied": ["artifacts"],
        "guided_fixes": [{"check": "roe", "fix": "Recreate examples/roe.yaml"}],
        "provider_readiness": {"ready": False, "detail": "offline"},
    }
    text = cli._doctor_human(failing, enabled=False)
    assert "FAIL roe: missing" in text
    assert "FIXED local folders: artifacts" in text
    assert "NEXT roe: Recreate examples/roe.yaml" in text
    assert "Suggested next steps" in text and "Activate.ps1" in text
    passing = cli._doctor_human({"passed": True, "checks": [{"passed": True, "name": "python", "detail": "3.11"}], "fixes_applied": [], "guided_fixes": []}, enabled=False)
    assert "READY" in passing and "PASS python: 3.11" in passing


def _fake_tty(value):
    return type("S", (), {"isatty": staticmethod(lambda: value)})()


def test_pick_campaign_non_interactive_returns_none(monkeypatch):
    from adversaryflow import cli

    monkeypatch.setattr(cli.sys, "stdin", _fake_tty(False))
    monkeypatch.setattr(cli.sys, "stderr", _fake_tty(False))
    assert cli._pick_campaign("artifacts/campaigns") is None


def test_pick_campaign_interactive_selection(monkeypatch):
    from adversaryflow import cli

    monkeypatch.setattr(cli.sys, "stdin", _fake_tty(True))
    monkeypatch.setattr(cli.sys, "stderr", io.StringIO())
    cli.sys.stderr.isatty = lambda: True
    monkeypatch.setattr(cli, "list_campaigns", lambda _root: [{"campaign_id": "c-1", "status": "awaiting-approval"}, {"campaign_id": "c-2", "status": "completed"}])
    monkeypatch.setattr("builtins.input", lambda _prompt="": "2")
    assert cli._pick_campaign("artifacts/campaigns") == "c-2"


@pytest.mark.parametrize("answer", ["", "0", "9", "notanumber"])
def test_pick_campaign_invalid_choices_return_none(monkeypatch, answer):
    from adversaryflow import cli

    monkeypatch.setattr(cli.sys, "stdin", _fake_tty(True))
    stderr = io.StringIO()
    stderr.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    monkeypatch.setattr(cli, "list_campaigns", lambda _root: [{"campaign_id": "c-1", "status": "x"}])
    monkeypatch.setattr("builtins.input", lambda _prompt="": answer)
    assert cli._pick_campaign("artifacts/campaigns") is None


def test_pick_campaign_empty_and_error_paths(monkeypatch):
    from adversaryflow import cli

    stderr = io.StringIO()
    stderr.isatty = lambda: True
    monkeypatch.setattr(cli.sys, "stdin", _fake_tty(True))
    monkeypatch.setattr(cli.sys, "stderr", stderr)
    monkeypatch.setattr(cli, "list_campaigns", lambda _root: [])
    assert cli._pick_campaign("artifacts/campaigns") is None
    monkeypatch.setattr(cli, "list_campaigns", lambda _root: (_ for _ in ()).throw(ValueError("bad root")))
    assert cli._pick_campaign("artifacts/campaigns") is None
