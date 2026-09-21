#!/usr/bin/env python3
"""Verify that Python distributions contain the freshly built frontend assets."""
from __future__ import annotations

import argparse
import hashlib
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ASSETS = ("index.html", "styles.css", "app.js", "favicon.svg")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _only_distribution(directory: Path, pattern: str, label: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise SystemExit(
            f"Expected exactly one {label} in {directory}, found {len(matches)}."
        )
    return matches[0]


def _matching_members(
    names: list[str],
    asset: str,
    matches: Callable[[tuple[str, ...], str], bool],
) -> list[str]:
    return [
        name
        for name in names
        if matches(PurePosixPath(name.replace("\\", "/")).parts, asset)
    ]


def _wheel_asset(archive: zipfile.ZipFile, asset: str) -> bytes:
    expected_tail = ("share", "adversaryflow", "frontend", asset)
    matches = _matching_members(
        archive.namelist(), asset, lambda parts, _asset: parts[-4:] == expected_tail
    )
    if len(matches) != 1:
        raise SystemExit(
            f"Wheel must contain exactly one share/adversaryflow/frontend/{asset}; "
            f"found {len(matches)}."
        )
    return archive.read(matches[0])


def _sdist_asset(archive: tarfile.TarFile, asset: str) -> bytes:
    members = archive.getmembers()
    matches = [
        member
        for member in members
        if len(PurePosixPath(member.name.replace("\\", "/")).parts) == 3
        and PurePosixPath(member.name.replace("\\", "/")).parts[-2:] == ("frontend", asset)
    ]
    if len(matches) != 1 or not matches[0].isfile():
        raise SystemExit(
            f"Source distribution must contain exactly one regular frontend/{asset}; "
            f"found {len(matches)}."
        )
    handle = archive.extractfile(matches[0])
    if handle is None:  # pragma: no cover - guarded by isfile()
        raise SystemExit(f"Could not read frontend/{asset} from source distribution.")
    return handle.read()


def _verify_bytes(label: str, asset: str, expected: bytes, actual: bytes) -> None:
    if actual != expected:
        raise SystemExit(
            f"{label} frontend/{asset} does not match the fresh build "
            f"(expected sha256:{_digest(expected)}, found sha256:{_digest(actual)})."
        )


def verify_distributions(directory: Path, source_root: Path = ROOT) -> None:
    wheel = _only_distribution(directory, "*.whl", "wheel")
    sdist = _only_distribution(directory, "*.tar.gz", "source distribution")
    expected = {
        asset: (source_root / "frontend" / asset).read_bytes()
        for asset in FRONTEND_ASSETS
    }

    try:
        with zipfile.ZipFile(wheel) as archive:
            for asset, content in expected.items():
                _verify_bytes("Wheel", asset, content, _wheel_asset(archive, asset))
        with tarfile.open(sdist, mode="r:gz") as archive:
            for asset, content in expected.items():
                _verify_bytes(
                    "Source distribution", asset, content, _sdist_asset(archive, asset)
                )
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        raise SystemExit(f"Could not inspect Python distributions: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=ROOT / "dist",
        help="directory containing exactly one wheel and one .tar.gz source distribution",
    )
    args = parser.parse_args()
    verify_distributions(args.dist_dir.resolve())
    print("Python distributions contain the fresh frontend assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
