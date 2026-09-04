#!/usr/bin/env python3
"""Fail a release when its tag, package version, or changelog disagree."""
from __future__ import annotations

import argparse
from pathlib import Path

from backend import __version__


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    expected = f"v{__version__}"
    if args.tag != expected:
        raise SystemExit(f"release tag {args.tag!r} does not match package version {expected!r}")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {__version__} " not in changelog:
        raise SystemExit(f"CHANGELOG.md has no {__version__} release section")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
