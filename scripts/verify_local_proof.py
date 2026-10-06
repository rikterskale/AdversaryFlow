"""Verify a local proof bundle against its separately pinned SHA-256 digest."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(bundle: Path, expected_sha256: str, repository: Path) -> None:
    if digest(bundle.read_bytes()) != expected_sha256.lower():
        raise ValueError("Proof bundle SHA-256 does not match the pinned digest")
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Proof bundle contains duplicate entries")
        manifest = json.loads(archive.read("manifest.json"))
        expected = manifest["files"]
        if set(names) != {*expected, "manifest.json"}:
            raise ValueError("Proof bundle file set differs from the manifest")
        for name, metadata in expected.items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name:
                raise ValueError("Proof bundle contains unsafe paths")
            data = archive.read(name)
            if len(data) != metadata["bytes"] or digest(data) != metadata["sha256"]:
                raise ValueError(f"Proof file does not match its digest: {name}")
        revision = manifest["implementation_commit"]
        if not all(isinstance(manifest[key], str) and re.fullmatch("[0-9a-f]{40}", manifest[key])
                   for key in ("implementation_commit", "implementation_tree", "base_commit")):
            raise ValueError("Proof Git identities are invalid")
        tree = subprocess.check_output(["git", "rev-parse", f"{revision}^{{tree}}"], cwd=repository, text=True).strip()
        if tree != manifest["implementation_tree"]:
            raise ValueError("Implementation tree differs from proof manifest")
        parent = subprocess.check_output(["git", "rev-parse", f"{revision}^"], cwd=repository, text=True).strip()
        if parent != manifest["base_commit"]:
            raise ValueError("Implementation parent differs from proof baseline")
        if len(manifest["findings"]) != 13 or {item["id"] for item in manifest["findings"]} != set(range(1, 14)):
            raise ValueError("Proof does not map all thirteen findings")
        results = [json.loads(archive.read(name)) for name in names if name.startswith("checks/") and name.endswith(".result.json")]
        if not results or any(item["exit_code"] != 0 for item in results):
            raise ValueError("A final verification command failed or is missing")
    print(f"Verified bundle SHA-256, every file, 13-case mapping, passing final commands and Git tree {tree}.")
    print("This is content-addressed and tamper-evident evidence, not independent timestamping, authorship authentication or deletion prevention.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    verify(args.bundle.resolve(), args.sha256, args.repository.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
