#!/usr/bin/env python3
"""Fail a release when its tag, package version, or changelog disagree."""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    source = Path("backend/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']$', source, re.MULTILINE)
    if not match:
        raise SystemExit("Could not read backend.__version__")
    version = match.group(1)
    expected = f"v{version}"
    if args.tag != expected:
        raise SystemExit(f"release tag {args.tag!r} does not match package version {expected!r}")
    changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version} " not in changelog:
        raise SystemExit(f"CHANGELOG.md has no {version} release section")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
