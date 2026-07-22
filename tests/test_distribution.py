from pathlib import Path
import tomllib


ROOT = Path(__file__).parents[1]


def test_distribution_excludes_local_sensitive_state() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    excluded = set(config["tool"]["hatch"]["build"]["exclude"])

    assert {"/.env", "/.claude", "/.adversaryflow", "/.venv", "/.test-tmp"} <= excluded


def test_docker_context_excludes_local_sensitive_state() -> None:
    excluded = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }

    assert {".env", ".claude", ".adversaryflow", ".venv", ".git"} <= excluded
