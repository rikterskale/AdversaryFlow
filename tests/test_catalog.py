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
                    self.assertTrue({
                        "platform", "command", "note", "cleanup", "risk", "side_effects",
                        "requires_admin", "requires_network", "network_targets", "prerequisites",
                        "expected_telemetry", "expected_output", "timeout_seconds", "rollback",
                        "cleanup_required", "acknowledgment_required",
                    }.issubset(command))
                    self.assertTrue(command["platform"])
                    self.assertTrue(command["command"])
                    self.assertIn(command["risk"], {"low", "medium", "high"})
                    self.assertEqual(command["cleanup_required"], bool(command["cleanup"]))

    def test_high_risk_commands_require_acknowledgment(self):
        for commands in command_catalog.CURATED.values():
            for command in commands:
                if command["risk"] == "high":
                    self.assertTrue(command["acknowledgment_required"])

    def test_missing_technique_uses_explicit_fallback(self):
        result = command_catalog.get_commands("T9999", "Fixture", ["execution"])
        self.assertEqual(result["source"], "fallback")
        self.assertIn("T9999", result["commands"][0]["command"])
        self.assertIn("risk", result["commands"][0])

    def test_bounded_simulations_are_observable_actions_not_no_ops(self):
        simulations = []
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                if "bounded lab simulation" not in command["note"].lower():
                    continue
                simulations.append(technique_id)
                self.assertNotIn(" echo ", command["command"].lower())
                self.assertTrue(command["cleanup_required"])
                self.assertIn("changes_local_state", command["side_effects"])
                self.assertTrue(
                    "Set-Content" in command["command"] or "printf" in command["command"],
                    command["command"],
                )
        self.assertGreaterEqual(len(simulations), 140)


if __name__ == "__main__":
    unittest.main()
