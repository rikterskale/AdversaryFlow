#!/usr/bin/env python3
"""Cross-platform developer task runner for AdversaryFlow.

This replaces the Unix-only Makefile with a single script that behaves
identically on Windows, Linux, and macOS. It only uses the Python standard
library, so the only prerequisite is a Python 3.11+ interpreter.

Usage:
    python tasks.py setup      # create .venv and install the project (+dev tools)
    python tasks.py test       # run the test suite
    python tasks.py lint       # ruff lint + format check
    python tasks.py format     # apply ruff formatting
    python tasks.py check      # lint + test (what CI runs)
    python tasks.py demo       # generate the deterministic demo report
    python tasks.py clean      # remove development caches/build output; preserve stored runs
    python tasks.py help       # show this message

Every command runs inside the project's virtual environment when one exists.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
IS_WINDOWS = sys.platform.startswith("win")


def venv_bin(name: str) -> Path:
    """Return the path to an executable inside the virtual environment."""
    if IS_WINDOWS:
        return VENV / "Scripts" / f"{name}.exe"
    return VENV / "bin" / name


def venv_python() -> str:
    """Prefer the venv interpreter; fall back to the current one."""
    candidate = venv_bin("python")
    return str(candidate) if candidate.exists() else sys.executable


def run(cmd: list[str], *, check: bool = True) -> int:
    """Run a command from the project root, echoing it first."""
    printable = " ".join(str(part) for part in cmd)
    print(f"$ {printable}", flush=True)
    result = subprocess.run(cmd, cwd=ROOT)
    if check and result.returncode != 0:
        sys.exit(result.returncode)
    return result.returncode


def ensure_venv() -> None:
    if not venv_bin("python").exists():
        print(f"Creating virtual environment in {VENV} ...", flush=True)
        run([sys.executable, "-m", "venv", str(VENV)])


def task_setup() -> None:
    ensure_venv()
    py = venv_python()
    run([py, "-m", "pip", "install", "--upgrade", "pip"])
    run([py, "-m", "pip", "install", "-e", ".[dev]"])
    env_file = ROOT / ".env"
    example = ROOT / ".env.example"
    if example.exists() and not env_file.exists():
        shutil.copyfile(example, env_file)
        print("Created .env from .env.example (edit it for live providers/search).")
    print("\nSetup complete. Try:  python tasks.py demo")


def task_test() -> None:
    run([venv_python(), "-m", "pytest", "-q"])


def task_lint() -> None:
    py = venv_python()
    run([py, "-m", "ruff", "check", "src", "tests"])
    run([py, "-m", "ruff", "format", "--check", "src", "tests"])


def task_format() -> None:
    run([venv_python(), "-m", "ruff", "format", "src", "tests"])


def task_check() -> None:
    task_lint()
    task_test()


def task_demo() -> None:
    run(
        [
            venv_python(),
            "-m",
            "adversaryflow.cli",
            "generate",
            "--request",
            "examples/apt29_request.json",
            "--output",
            "reports/apt29_scenario.md",
            "--demo",
        ]
    )


def task_clean() -> None:
    directories = [
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "dist",
    ]
    for name in directories:
        target = ROOT / name
        if target.exists():
            print(f"Removing {target}")
            shutil.rmtree(target, ignore_errors=True)

    for egg_info in ROOT.glob("src/*.egg-info"):
        print(f"Removing {egg_info}")
        shutil.rmtree(egg_info, ignore_errors=True)

    for pycache in ROOT.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)

    # Remove generated reports but keep the tracked demo artifacts.
    keep = {"apt29_scenario.md", "apt29_scenario.trace.json"}
    reports = ROOT / "reports"
    if reports.exists():
        for item in reports.iterdir():
            if item.is_file() and item.name not in keep:
                print(f"Removing {item}")
                item.unlink()
    print("Clean complete. Durable runs and caches under .adversaryflow were preserved.")


TASKS = {
    "setup": task_setup,
    "test": task_test,
    "lint": task_lint,
    "format": task_format,
    "check": task_check,
    "demo": task_demo,
    "clean": task_clean,
}


def task_help() -> None:
    print(__doc__)
    print("Available commands: " + ", ".join(TASKS) + ", help")


def main(argv: list[str]) -> int:
    if sys.version_info < (3, 11):
        print(
            "AdversaryFlow requires Python 3.11 or newer. "
            f"This interpreter is Python {sys.version_info.major}.{sys.version_info.minor}.",
            file=sys.stderr,
        )
        return 1
    if not argv or argv[0] in {"help", "-h", "--help"}:
        task_help()
        return 0
    command = argv[0]
    handler = TASKS.get(command)
    if handler is None:
        print(f"Unknown command: {command}\n", file=sys.stderr)
        task_help()
        return 2
    handler()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
