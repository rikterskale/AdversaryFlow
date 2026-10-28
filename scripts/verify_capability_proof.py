"""Verify five-step evidence against a separately pinned archive SHA-256.

The digest proves content identity. It does not prove an independent time,
authorship, deletion prevention, or that self-reported tests are honest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_archive(bundle: Path, pinned: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", pinned) or sha(bundle.read_bytes()) != pinned.lower():
        raise ValueError("Archive differs from the separately pinned SHA-256")
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate archive entries")
        if sum(entry.file_size for entry in entries) > 400_000_000:
            raise ValueError("Archive exceeds the verification size budget")
        for name in names:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts:
                raise ValueError("Unsafe archive path")
        manifest = json.loads(archive.read("manifest.json"))
        if set(names) != {"manifest.json", *manifest["files"]}:
            raise ValueError("Archive file set differs from manifest")
        for name, item in manifest["files"].items():
            data = archive.read(name)
            if len(data) != item["bytes"] or sha(data) != item["sha256"]:
                raise ValueError(f"File digest mismatch: {name}")
        previous = sha(archive.read("baseline-files.json"))
        for step in range(1, 6):
            prefix = f"stages/step-{step}/"
            raw = archive.read(prefix + "manifest.json")
            stage = json.loads(raw)
            if stage["step"] != step or stage["previous_sha256"] != previous or stage["exit_code"] != 0:
                raise ValueError(f"Invalid completion chain at step {step}")
            for name, digest in stage["source_files"].items():
                if sha(archive.read(prefix + "source/" + name)) != digest:
                    raise ValueError(f"Stage source mismatch: {step}/{name}")
            logs = stage.get("logs", {"checks.log": stage.get("log_sha256")})
            for name, digest in logs.items():
                if digest is None or sha(archive.read(prefix + name)) != digest:
                    raise ValueError(f"Stage log mismatch: {step}/{name}")
            previous = sha(raw)
        if previous != manifest["final_stage_sha256"]:
            raise ValueError("Final stage digest mismatch")
        checks = manifest["required_checks"]
        if not checks or len(checks) != len(set(checks)):
            raise ValueError("Missing or duplicate required checks")
        for name in checks:
            result = json.loads(archive.read(f"checks/{name}.result.json"))
            if result["exit_code"] != 0 or result["source_manifest_sha256"] != manifest["source_manifest_sha256"]:
                raise ValueError(f"Failed check or wrong source snapshot: {name}")
            if sha(archive.read(f"checks/{name}.log")) != result["log_sha256"]:
                raise ValueError(f"Check log mismatch: {name}")
        source = json.loads(archive.read("source-files.json"))
        if sha(archive.read("source-files.json")) != manifest["source_manifest_sha256"]:
            raise ValueError("Source manifest mismatch")
        if {n for n in names if n.startswith("source/")} != {"source/" + n for n in source}:
            raise ValueError("Source file set mismatch")
        for name, digest in source.items():
            if sha(archive.read("source/" + name)) != digest:
                raise ValueError(f"Final source mismatch: {name}")
        summary = json.loads(archive.read("coverage/summary.json"))
        receipt_names = [n for n in names if n.startswith("coverage/receipts/") and n.endswith(".json")]
        if len(receipt_names) != summary["bounded_exercises"] or summary["receipts_passed"] != len(receipt_names):
            raise ValueError("Missing bounded exercise receipts")
        for name in receipt_names:
            receipt = json.loads(archive.read(name))
            digest = receipt.pop("receipt_sha256")
            if (sha(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()) != digest
                    or receipt["status"] != "passed" or receipt["exit_code"] != 0 or not receipt["cleanup_verified"]):
                raise ValueError(f"Invalid or failed fixture receipt: {name}")
        if sha(archive.read("inputs/enterprise-attack.json")) != summary["bundle_sha256"]:
            raise ValueError("ATT&CK input mismatch")
        for key in ("implementation_commit", "implementation_tree", "base_commit"):
            if not re.fullmatch(r"[0-9a-f]{40}", manifest[key]):
                raise ValueError("Invalid Git identity")
    return manifest


def verify_git(bundle: Path, manifest: dict[str, Any], repository: Path) -> None:
    revision = manifest["implementation_commit"]
    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=repository)
    if git("rev-parse", f"{revision}^{{tree}}").decode().strip() != manifest["implementation_tree"]:
        raise ValueError("Git tree differs from proof")
    if git("rev-parse", f"{revision}^").decode().strip() != manifest["base_commit"]:
        raise ValueError("Git parent differs from baseline")
    with zipfile.ZipFile(bundle) as archive:
        source = json.loads(archive.read("source-files.json"))
        files = git("ls-tree", "-rz", revision).split(b"\0")
        tree_files = {}
        for entry in files:
            if entry:
                metadata, raw_name = entry.split(b"\t", 1)
                mode, kind, raw_oid = metadata.split()
                if kind != b"blob" or mode not in {b"100644", b"100755"}:
                    raise ValueError("Proof source must contain regular files")
                tree_files[raw_name.decode()] = raw_oid.decode()
        if set(tree_files) != set(source):
            raise ValueError("Git source file set differs from proof")
        for name, oid in tree_files.items():
            if sha(git("cat-file", "blob", oid)) != source[name]:
                raise ValueError(f"Git source differs from proof: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    manifest = verify_archive(args.bundle, args.sha256)
    verify_git(args.bundle, manifest, args.repository)
    print(f"Verified all five chained stages, source/Git tree, {len(manifest['required_checks'])} passing checks and every fixture receipt.")
    print("Content-addressed, tamper-evident evidence; no independent timestamp, signature or deletion protection.")


if __name__ == "__main__":
    main()
