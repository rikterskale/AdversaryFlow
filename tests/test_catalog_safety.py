import os
import shutil
import subprocess
import unittest

from backend import command_catalog


class CatalogSafetyTests(unittest.TestCase):
    def commands(self):
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                yield technique_id, command

    def test_no_fixed_lab_account_passwords(self):
        for technique_id, command in self.commands():
            with self.subTest(technique_id=technique_id):
                self.assertNotIn("P@ss", command["command"])

    def test_network_classification_matches_known_markers(self):
        markers = ("http://", "https://", "nslookup", "resolve-dnsname", "test-netconnection")
        for technique_id, command in self.commands():
            if any(marker in command["command"].lower() for marker in markers):
                with self.subTest(technique_id=technique_id):
                    self.assertTrue(command["requires_network"])

    def test_mutating_high_risk_commands_are_acknowledged(self):
        for technique_id, command in self.commands():
            with self.subTest(technique_id=technique_id):
                if command["risk"] == "high":
                    self.assertTrue(command["acknowledgment_required"])
                if command["cleanup_required"]:
                    self.assertEqual(command["rollback"], command["cleanup"])

    @unittest.skipIf(os.name == "nt", "POSIX command parsing is covered by Linux and macOS jobs")
    @unittest.skipUnless(shutil.which("bash"), "bash parser is unavailable")
    def test_posix_commands_parse_without_execution(self):
        for technique_id, command in self.commands():
            if command["platform"] not in {"linux", "macos"}:
                continue
            result = subprocess.run(
                ["bash", "-n", "-c", command["command"]],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            with self.subTest(technique_id=technique_id, command=command["command"]):
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
