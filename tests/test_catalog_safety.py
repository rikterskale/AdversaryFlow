import re
import shlex
import shutil
import subprocess
import unittest

from backend import command_catalog

FORBIDDEN_LIVE_PATTERNS = (
    r"reg save\b",
    r"sc\.exe create",
    r"lockworkstation",
    r"net user\s+\S+.*\/add",
    r"https?://example\.com",
    r"ifconfig\.me",
    r"169\.254\.169\.254",
    r"findstr /si password",
    r"git ls-remote https://",
    r"start-process 'https://",
    r"downloadstring\('https://",
)


class CatalogSafetyTests(unittest.TestCase):
    def commands(self):
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                yield technique_id, command

    def test_the_catalog_does_not_ship_live_mutators_or_third_party_fetches(self):
        compiled = [re.compile(pattern, re.IGNORECASE) for pattern in FORBIDDEN_LIVE_PATTERNS]
        for technique_id, command in self.commands():
            text = command["command"]
            for pattern in compiled:
                with self.subTest(technique_id=technique_id, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text), text)

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

    def test_posix_commands_parse_without_execution(self):
        bash = shutil.which("bash")
        for technique_id, command in self.commands():
            if command["platform"] not in {"linux", "macos", "pre"}:
                continue
            with self.subTest(technique_id=technique_id, command=command["command"]):
                self.assertTrue(shlex.split(command["command"], posix=True))
                if bash:
                    result = subprocess.run(
                        [bash, "-n", "-c", command["command"]],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
