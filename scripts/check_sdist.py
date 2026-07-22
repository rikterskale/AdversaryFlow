#!/usr/bin/env python3
"""Assert that a built source distribution contains nothing outside the allowlist.

The sdist allowlist in ``pyproject.toml`` is the intended contract. This script
checks that the artifact actually honors it, which the allowlist alone cannot
guarantee: a build backend upgrade, a stray ``force-include``, or a future edit
that reintroduces a denylist would all pass configuration review and still ship
files nobody meant to publish.

That failure mode is not hypothetical here. A scenario request enumerates
environment names, identity systems, security tooling, crown jewels, designated
test assets, authorized users, and rules of engagement, and ``USAGE.md`` tells
operators to create one inside the checkout.

Usage:
    python scripts/check_sdist.py                    # newest dist/*.tar.gz
    python scripts/check_sdist.py path/to/pkg.tar.gz # an explicit artifact

Exits 0 when the artifact is clean, 1 when it contains unexpected paths, and 2
when it cannot check (no artifact, unreadable configuration).

Standard library only, so it runs anywhere ``tasks.py`` runs.
"""

from __future__ import annotations

import sys
import tarfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Metadata the build backend generates inside the archive. These never exist in
# the working tree, so they cannot appear in the allowlist.
GENERATED_MEMBERS = frozenset({"PKG-INFO"})

# Exit 2 means "could not perform the check", which is distinct from exit 1,
# "checked it and it failed". CI must not read the former as a pass.
CANNOT_CHECK = 2


def _cannot_check(message: str) -> SystemExit:
    print(message, file=sys.stderr)
    return SystemExit(CANNOT_CHECK)


def read_allowlist(pyproject: Path) -> list[str]:
    """Return the configured sdist include patterns, without leading slashes."""
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    try:
        include = config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    except KeyError:
        raise _cannot_check(
            "No [tool.hatch.build.targets.sdist] include list found in "
            f"{pyproject}. The source distribution must be built from an "
            "explicit allowlist, not a denylist."
        ) from None
    if not include:
        raise _cannot_check("The sdist include list is empty; refusing to check nothing.")
    return [str(entry).lstrip("/").rstrip("/") for entry in include]


def strip_root(member: str) -> str | None:
    """Drop the ``name-version/`` directory every sdist wraps its contents in."""
    _, separator, remainder = member.partition("/")
    if not separator or not remainder:
        return None
    return remainder


def is_allowed(path: str, allowlist: list[str]) -> bool:
    """True when ``path`` is an allowlist entry or lives beneath one."""
    if path in GENERATED_MEMBERS:
        return True
    return any(path == entry or path.startswith(f"{entry}/") for entry in allowlist)


def unexpected_paths(members: list[str], allowlist: list[str]) -> list[str]:
    """Return sorted archive paths that the allowlist does not account for."""
    offenders = set()
    for member in members:
        path = strip_root(member)
        if path is None:
            continue
        if not is_allowed(path, allowlist):
            offenders.add(path)
    return sorted(offenders)


def newest_sdist(dist_dir: Path) -> Path:
    if not dist_dir.is_dir():
        raise _cannot_check(f"No {dist_dir} directory. Run `python -m build` first.")
    candidates = sorted(dist_dir.glob("*.tar.gz"), key=lambda item: item.stat().st_mtime)
    if not candidates:
        raise _cannot_check(
            f"No source distribution found in {dist_dir}. Run `python -m build` first."
        )
    return candidates[-1]


def main(argv: list[str]) -> int:
    if argv:
        archive = Path(argv[0])
        if not archive.is_file():
            print(f"Not a file: {archive}", file=sys.stderr)
            return CANNOT_CHECK
    else:
        archive = newest_sdist(ROOT / "dist")

    allowlist = read_allowlist(ROOT / "pyproject.toml")
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getnames()

    offenders = unexpected_paths(members, allowlist)
    if offenders:
        print(f"{archive.name} contains {len(offenders)} unexpected path(s):", file=sys.stderr)
        for path in offenders:
            print(f"  {path}", file=sys.stderr)
        print(
            "\nEither add the path to [tool.hatch.build.targets.sdist] include "
            "in pyproject.toml, or stop packaging it. Treat any scenario "
            "request, report, trace, or run store here as an exercise-data "
            "disclosure and do not publish this artifact.",
            file=sys.stderr,
        )
        return 1

    print(f"{archive.name}: {len(members)} members, all within the sdist allowlist.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
