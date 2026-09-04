import unittest

from backend import command_catalog
from backend.command_catalog_extended import EXTENDED
from backend.lab_exercises import TECHNIQUE_SCENARIOS


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

    def test_bounded_exercises_are_technique_specific_and_disclosed(self):
        exercises = {}
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                if command.get("exercise_kind") != "technique_relevant_bounded":
                    continue
                exercises[technique_id] = command
                self.assertEqual(command["command"].split()[-1], technique_id)
                self.assertTrue(command["expected_telemetry"])
                self.assertIn("self-reported evidence", command["note"])
                self.assertFalse(command["requires_admin"])
                self.assertFalse(command["cleanup_required"])
                self.assertEqual(command["telemetry_acceptance"]["technique_id"], technique_id)
        self.assertEqual(len(exercises), 146)
        self.assertEqual(set(exercises), set(TECHNIQUE_SCENARIOS))
        self.assertEqual(len({command["command"] for command in exercises.values()}), 146)
        for technique_id in exercises:
            records = [command for command in command_catalog.CURATED[technique_id] if command.get("exercise_kind")]
            self.assertEqual({command["platform"] for command in records}, {"windows", "linux", "macos"})

    def test_catalog_record_counts_are_explicit(self):
        self.assertEqual(sum(len(commands) for commands in command_catalog.CURATED.values()), 848)


if __name__ == "__main__":
    unittest.main()
