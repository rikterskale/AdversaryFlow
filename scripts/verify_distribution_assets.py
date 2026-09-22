#!/usr/bin/env python3
"""Verify packaged frontend assets and the source distribution's rebuild inputs."""
from __future__ import annotations

import argparse
import hashlib
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ASSETS = ("index.html", "styles.css", "app.js", "favicon.svg")
FRONTEND_BUILD_FILES = (
    "package.json",
    "package-lock.json",
    "frontend/package.json",
    "frontend/vite.config.ts",
    "frontend/vitest.config.ts",
    "frontend/tsconfig.json",
    "frontend/postcss.config.cjs",
    "frontend/tailwind.config.js",
)


def _frontend_build_inputs(source_root: Path) -> list[str]:
    inputs = list(FRONTEND_BUILD_FILES)
    for directory in ("frontend/src", "frontend/public"):
        files = sorted(
            path for path in (source_root / directory).rglob("*")
            if path.is_file() and "node_modules" not in path.relative_to(source_root).parts
        )
        if not files:
            raise SystemExit(f"No frontend build inputs found in {directory}.")
        inputs.extend(path.relative_to(source_root).as_posix() for path in files)
    return inputs


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


def _sdist_file(archive: tarfile.TarFile, path: str) -> bytes:
    members = archive.getmembers()
    matches = [
        member
        for member in members
        if PurePosixPath(member.name.replace("\\", "/")).parts[1:] == PurePosixPath(path).parts
    ]
    if len(matches) != 1 or not matches[0].isfile():
        raise SystemExit(
            f"Source distribution must contain exactly one regular {path}; "
            f"found {len(matches)}."
        )
    handle = archive.extractfile(matches[0])
    if handle is None:  # pragma: no cover - guarded by isfile()
        raise SystemExit(f"Could not read {path} from source distribution.")
    return handle.read()


def _verify_bytes(label: str, path: str, expected: bytes, actual: bytes) -> None:
    if actual != expected:
        raise SystemExit(
            f"{label} {path} does not match the source tree "
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
                _verify_bytes("Wheel", f"frontend/{asset}", content, _wheel_asset(archive, asset))
        with tarfile.open(sdist, mode="r:gz") as archive:
            for asset, content in expected.items():
                _verify_bytes(
                    "Source distribution", f"frontend/{asset}", content, _sdist_file(archive, f"frontend/{asset}")
                )
            for path in _frontend_build_inputs(source_root):
                _verify_bytes(
                    "Source distribution build input", path,
                    (source_root / path).read_bytes(), _sdist_file(archive, path),
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
    print("Python distributions contain the fresh frontend assets and source rebuild inputs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
