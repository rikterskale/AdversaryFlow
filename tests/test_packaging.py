import tomllib
from pathlib import Path


def test_console_entry_point_is_declared():
    with Path("pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    assert project["scripts"]["adversaryflow"] == "adversaryflow.cli:main"
