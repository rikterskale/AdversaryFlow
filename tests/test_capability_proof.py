import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify_capability_proof import verify_archive


class CapabilityProofTests(unittest.TestCase):
    def test_rejects_archive_changed_after_digest_was_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.zip"
            path.write_bytes(b"original")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "separately pinned"):
                verify_archive(path, digest)

    def test_rejects_duplicate_and_unsafe_entries_even_with_a_matching_archive_hash(self):
        for names in (("../source.py",), ("duplicate", "duplicate")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "proof.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for name in names:
                        archive.writestr(name, "fixture")
                with self.assertRaisesRegex(ValueError, "Duplicate|Unsafe"):
                    verify_archive(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_rejects_internal_file_tampering_even_if_outer_hash_is_recomputed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("source.py", "changed")
                archive.writestr("manifest.json", json.dumps({"files": {"source.py": {
                    "sha256": hashlib.sha256(b"original").hexdigest(), "bytes": len(b"original")}}}))
            with self.assertRaisesRegex(ValueError, "File digest mismatch"):
                verify_archive(path, hashlib.sha256(path.read_bytes()).hexdigest())
