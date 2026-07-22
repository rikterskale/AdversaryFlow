import importlib.util
import sys
from pathlib import Path
import tomllib

import pytest


ROOT = Path(__file__).parents[1]


def _load_check_sdist():
    """Import scripts/check_sdist.py, which is a dev tool and not on the path."""
    path = ROOT / "scripts" / "check_sdist.py"
    spec = importlib.util.spec_from_file_location("check_sdist", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_sdist"] = module
    spec.loader.exec_module(module)
    return module


check_sdist = _load_check_sdist()


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


def test_source_distribution_is_built_from_an_allowlist() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]

    assert include, "The sdist must be built from an explicit include list."
    assert {"/src", "/pyproject.toml", "/README.md", "/LICENSE"} <= set(include)


def test_allowlist_entries_all_exist() -> None:
    """A stale entry silently widens nothing, but it hides real drift."""
    allowlist = check_sdist.read_allowlist(ROOT / "pyproject.toml")

    missing = [entry for entry in allowlist if not (ROOT / entry).exists()]

    assert not missing, f"sdist allowlist names paths that no longer exist: {missing}"


def test_checker_accepts_an_artifact_within_the_allowlist() -> None:
    members = [
        "adversaryflow-0.3.0/",
        "adversaryflow-0.3.0/PKG-INFO",
        "adversaryflow-0.3.0/pyproject.toml",
        "adversaryflow-0.3.0/src/adversaryflow/cli.py",
        "adversaryflow-0.3.0/examples/tabletop_request.json",
        "adversaryflow-0.3.0/data/.gitkeep",
    ]
    allowlist = ["src", "examples", "data/.gitkeep", "pyproject.toml"]

    assert check_sdist.unexpected_paths(members, allowlist) == []


@pytest.mark.parametrize(
    "leaked",
    [
        "my-request.json",
        "scenario-request.schema.json",
        "artifacts/scenario.md",
        "reports/exercise.trace.json",
        ".adversaryflow/runs/20260101T000000Z-abc/manifest.json",
        ".env",
    ],
)
def test_checker_rejects_exercise_data_and_local_state(leaked: str) -> None:
    """These are the paths a maintainer would actually leak from a dirty tree."""
    members = [
        "adversaryflow-0.3.0/pyproject.toml",
        f"adversaryflow-0.3.0/{leaked}",
    ]
    allowlist = ["src", "examples", "pyproject.toml"]

    assert check_sdist.unexpected_paths(members, allowlist) == [leaked]


def test_checker_does_not_treat_a_prefix_match_as_containment() -> None:
    """`src` must not authorize a sibling named `src-scratch`."""
    members = [
        "adversaryflow-0.3.0/src/adversaryflow/cli.py",
        "adversaryflow-0.3.0/src-scratch/notes.md",
        "adversaryflow-0.3.0/examples-private/client.json",
    ]
    allowlist = ["src", "examples"]

    assert check_sdist.unexpected_paths(members, allowlist) == [
        "examples-private/client.json",
        "src-scratch/notes.md",
    ]


def test_checker_rejects_a_denylist_configuration(tmp_path: Path) -> None:
    """Reverting to a denylist must fail loudly rather than check nothing."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.hatch.build]\nexclude = ["/.env"]\n', encoding="utf-8")

    with pytest.raises(SystemExit):
        check_sdist.read_allowlist(pyproject)
