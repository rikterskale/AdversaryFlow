import unittest

from backend import command_catalog
from backend.command_catalog_extended import EXTENDED


class CatalogIntegrityTests(unittest.TestCase):
    def test_expected_catalog_size(self):
        self.assertEqual(len(EXTENDED), 437)
        self.assertEqual(len(command_catalog.CURATED), 533)

    def test_entries_have_complete_shape(self):
        for technique_id, commands in command_catalog.CURATED.items():
            with self.subTest(technique_id=technique_id):
                self.assertTrue(technique_id.startswith("T"))
                self.assertTrue(commands)
                for command in commands:
                    self.assertEqual(set(command), {"platform", "command", "note", "cleanup"})
                    self.assertTrue(command["platform"])
                    self.assertTrue(command["command"])

    def test_missing_technique_uses_explicit_fallback(self):
        result = command_catalog.get_commands("T9999", "Fixture", ["execution"])
        self.assertEqual(result["source"], "fallback")
        self.assertIn("T9999", result["commands"][0]["command"])


if __name__ == "__main__":
    unittest.main()
