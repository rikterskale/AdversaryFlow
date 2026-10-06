"""Exercise tamper detection without relying on an external timestamp authority."""
from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tests.test_scripts import load

verify_local_proof = load("verify_local_proof")
digest = verify_local_proof.digest
verify = verify_local_proof.verify


class LocalProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / "proof.zip"
        self.content = json.dumps({"exit_code": 0}).encode()
        self.findings = [{"id": number} for number in range(1, 14)]
        self.files: dict[str, dict[str, int | str]] = {
            "checks/check.result.json": {"bytes": len(self.content), "sha256": digest(self.content)},
        }
        self.manifest: dict[str, object] = {
            "implementation_commit": "a" * 40,
            "implementation_tree": "b" * 40,
            "base_commit": "c" * 40,
            "findings": self.findings,
            "files": self.files,
        }

    def write_bundle(self):
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("manifest.json", json.dumps(self.manifest))
            archive.writestr("checks/check.result.json", self.content)
        return digest(self.bundle.read_bytes())

    def validate(self):
        pinned_digest = self.write_bundle()
        with patch.object(verify_local_proof.subprocess, "check_output",
                   side_effect=["b" * 40, "c" * 40]):
            verify(self.bundle, pinned_digest, self.root)

    def test_complete_bundle_and_git_identity_pass(self):
        self.validate()

    def test_changed_bundle_rejected_against_original_pin(self):
        pinned_digest = self.write_bundle()
        self.bundle.write_bytes(self.bundle.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "pinned digest"):
            verify(self.bundle, pinned_digest, self.root)

    def test_changed_internal_file_rejected_even_with_new_bundle_pin(self):
        self.content += b" "
        with self.assertRaisesRegex(ValueError, "file does not match"):
            self.validate()

    def test_omitted_case_rejected(self):
        self.findings.pop()
        with self.assertRaisesRegex(ValueError, "thirteen"):
            self.validate()

    def test_failed_final_check_rejected(self):
        self.content = json.dumps({"exit_code": 1}).encode()
        self.files["checks/check.result.json"] = {
            "bytes": len(self.content), "sha256": digest(self.content),
        }
        with self.assertRaisesRegex(ValueError, "final verification"):
            self.validate()

    def test_git_option_injection_rejected_before_invocation(self):
        self.manifest["implementation_commit"] = "--git-dir=other"
        pinned_digest = self.write_bundle()
        with patch.object(verify_local_proof.subprocess, "check_output") as command:
            with self.assertRaisesRegex(ValueError, "Git identities"):
                verify(self.bundle, pinned_digest, self.root)
            command.assert_not_called()

    def test_wrong_git_tree_rejected(self):
        self.manifest["implementation_tree"] = "d" * 40
        with self.assertRaisesRegex(ValueError, "tree differs"):
            self.validate()

    def test_undeclared_file_rejected(self):
        self.write_bundle()
        with zipfile.ZipFile(self.bundle, "a") as archive:
            archive.writestr("unlisted.txt", "extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            verify(self.bundle, digest(self.bundle.read_bytes()), self.root)
