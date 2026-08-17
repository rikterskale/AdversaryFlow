"""Shared CLI output helpers: modes, colorized severity, and exit codes.

Every command routes its result through :func:`respond` so the three output
modes behave consistently:

* ``json``  – pretty JSON on stdout (the default when output is piped/redirected,
  which keeps scripts and the test-suite deterministic).
* ``human`` – readable, optionally colorized text (the default on an interactive
  terminal).
* ``quiet`` – a single terse status line, for CI and shell pipelines.

Color is emitted only when the stream is a real terminal and neither ``NO_COLOR``
nor ``--no-color`` is set, so redirected output is always plain and stable.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

JSON = "json"
HUMAN = "human"
QUIET = "quiet"


class ExitCode:
    """Documented, stable process exit codes.

    ``USAGE`` mirrors argparse's own exit code (2) for malformed invocations.
    The reserved codes give scripts a stable contract for branching on *why* a
    command failed closed; see :data:`EXIT_CODE_HELP`.
    """

    OK = 0
    ERROR = 1
    USAGE = 2
    SCOPE_VIOLATION = 3
    APPROVAL_REQUIRED = 4
    PROVIDER_ERROR = 5
    INTEGRITY_ERROR = 6
    NOT_FOUND = 7


EXIT_CODE_HELP: dict[int, str] = {
    ExitCode.OK: "Success. The command completed and any dry-run/plan output is above.",
    ExitCode.ERROR: "General error. The command failed; see the JSON 'error' field for detail.",
    ExitCode.USAGE: "Usage error. Arguments were missing or invalid (argparse-level).",
    ExitCode.SCOPE_VIOLATION: "Scope violation. A target or action was outside the Rules of Engagement.",
    ExitCode.APPROVAL_REQUIRED: "Approval required or refused. The named RoE approver must authorize this.",
    ExitCode.PROVIDER_ERROR: "Provider error. The hosted AI provider was unreachable or misconfigured; retry with --fallback-offline.",
    ExitCode.INTEGRITY_ERROR: "Integrity error. A saved plan, RoE, or ability catalog no longer matches its recorded hash.",
    ExitCode.NOT_FOUND: "Not found. The requested campaign, technique, or resource does not exist.",
}


# ANSI colours used only for interactive, human-mode severity lines.
_COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "amber": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
}


def supports_color(stream: Any = None, *, no_color: bool = False) -> bool:
    """Return True only when it is safe to emit ANSI colour."""
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _enable_windows_vt() -> None:
    """Best-effort enable of ANSI processing on legacy Windows consoles."""
    if sys.platform != "win32":
        return
    try:  # pragma: no cover - platform specific
        import ctypes

        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:  # nosec B110 - colour is cosmetic; never fail a command over it
        pass


def colorize(text: str, color: str, *, enabled: bool) -> str:
    if not enabled or color not in _COLORS:
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


_SEVERITY_COLORS = {"ok": "green", "good": "green", "pass": "green", "warn": "amber", "amber": "amber", "fail": "red", "bad": "red", "error": "red", "info": "cyan"}  # nosec B105 - severity->colour map, not a credential


def severity(label: str, message: str, level: str = "info", *, enabled: bool | None = None) -> str:
    """Render a single ``LABEL  message`` line, coloured by severity level."""
    if enabled is None:
        enabled = supports_color()
    if enabled:
        _enable_windows_vt()
    color = _SEVERITY_COLORS.get(level.lower(), "cyan")
    return f"{colorize(label, color, enabled=enabled)} {message}"


def resolve_mode(args: Any) -> str:
    """Pick the output mode from parsed args and terminal state."""
    if getattr(args, "quiet", False):
        return QUIET
    if getattr(args, "json", False):
        return JSON
    if getattr(args, "human", False):
        return HUMAN
    return HUMAN if supports_color(no_color=getattr(args, "no_color", False)) else JSON


def _quiet_line(payload: Any) -> str:
    if isinstance(payload, dict):
        if payload.get("error"):
            return f"error: {payload['error']}"
        for key in ("status", "stage", "campaign_id", "notice"):
            if payload.get(key):
                return str(payload[key])
        if "success" in payload:
            return "ok" if payload["success"] else "failed"
    return ""


def respond(args: Any, payload: Any, human: str | None = None, *, exit_code: int = 0) -> None:
    """Emit ``payload`` in the resolved mode, then optionally exit non-zero.

    When no ``human`` rendering is supplied the human mode falls back to pretty
    JSON, so behaviour is never worse than before a command grows a text view.
    """
    mode = resolve_mode(args)
    if mode == QUIET:
        line = _quiet_line(payload)
        if line:
            print(line)
    elif mode == HUMAN and human is not None:
        print(human)
    else:
        print(json.dumps(payload, indent=2))
    if exit_code:
        raise SystemExit(exit_code)


def progress(message: str, step: int | None = None, total: int | None = None, *, stream: Any = None) -> None:
    """Print a transient step indicator to stderr (interactive terminals only).

    Written to stderr so stdout stays a clean, parseable payload.
    """
    stream = stream or sys.stderr
    if not supports_color(stream):
        return
    prefix = f"[{step}/{total}] " if step and total else "… "
    stream.write(colorize(prefix, "cyan", enabled=True) + message + "\n")
    stream.flush()


def dry_run_banner(will: list[str], will_not: list[str], *, enabled: bool | None = None, stream: Any = None) -> None:
    """Print a compact will / will-not safety banner (interactive terminals only)."""
    stream = stream or sys.stderr
    if enabled is None:
        enabled = supports_color(stream)
    if not enabled:
        return
    _enable_windows_vt()
    stream.write(colorize("DRY RUN — no external target is contacted", "amber", enabled=enabled) + "\n")
    for item in will:
        stream.write("  " + colorize("will", "green", enabled=enabled) + f"     {item}\n")
    for item in will_not:
        stream.write("  " + colorize("will NOT", "red", enabled=enabled) + f" {item}\n")
    stream.flush()
