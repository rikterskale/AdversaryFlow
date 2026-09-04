"""Direct cover for the safety metadata derived for every catalog command."""
import unittest

from backend.command_safety import _network_targets, command_record, technique_exercise_record


class CommandRecordTests(unittest.TestCase):
    def test_a_read_only_command_is_classified_as_low_risk(self):
        record = command_record("windows", "whoami", "Read-only identity check.")
        self.assertEqual(record["risk"], "low")
        self.assertEqual(record["side_effects"], ["read_only_or_process_telemetry"])
        self.assertFalse(record["requires_network"])
        self.assertFalse(record["requires_admin"])
        self.assertFalse(record["cleanup_required"])
        self.assertFalse(record["acknowledgment_required"])
        self.assertEqual(record["network_targets"], [])
        self.assertEqual(record["timeout_seconds"], 60)
        self.assertEqual(record["rollback"], "")

    def test_the_full_contract_shape_is_always_present(self):
        record = command_record("linux", "id")
        self.assertEqual(set(record), {
            "platform", "command", "note", "cleanup", "risk", "side_effects",
            "requires_admin", "requires_network", "network_targets", "prerequisites",
            "expected_telemetry", "expected_output", "timeout_seconds", "rollback",
            "cleanup_required", "acknowledgment_required",
        })

    def test_prerequisites_name_the_platform_and_the_lab(self):
        record = command_record("macos", "sw_vers")
        self.assertEqual(record["prerequisites"], ["macos command environment", "authorized disposable lab"])

    def test_expected_output_falls_back_to_the_note_then_to_guidance(self):
        self.assertEqual(command_record("linux", "id", "Prints the user.")["expected_output"], "Prints the user.")
        self.assertIn("verify the expected telemetry", command_record("linux", "id")["expected_output"])

    def test_a_network_command_is_medium_risk_and_needs_acknowledgment(self):
        record = command_record("windows", "powershell -Command \"Invoke-WebRequest https://example.com\"")
        self.assertTrue(record["requires_network"])
        self.assertEqual(record["risk"], "medium")
        self.assertIn("network_activity", record["side_effects"])
        self.assertTrue(record["acknowledgment_required"])
        self.assertEqual(record["network_targets"], ["example.com"])

    def test_a_network_marker_in_the_note_alone_still_classifies(self):
        record = command_record("linux", "true", "Runs nslookup against the lab resolver.")
        self.assertTrue(record["requires_network"])

    def test_a_state_changing_command_is_medium_risk(self):
        record = command_record("windows", "reg add HKCU\\Software\\AdversaryFlowLab /v Marker /d 1 /f")
        self.assertEqual(record["risk"], "medium")
        self.assertIn("changes_local_state", record["side_effects"])
        self.assertFalse(record["requires_network"])

    def test_a_high_risk_marker_escalates_the_rating(self):
        record = command_record("windows", "schtasks /Create /TN AFLab /TR cmd.exe /SC ONCE /ST 23:59 /F",
                                "", "schtasks /Delete /TN AFLab /F")
        self.assertEqual(record["risk"], "high")
        self.assertTrue(record["acknowledgment_required"])
        self.assertTrue(record["cleanup_required"])
        self.assertEqual(record["rollback"], "schtasks /Delete /TN AFLab /F")

    def test_registry_hive_access_requires_admin(self):
        record = command_record("windows", "reg save HKLM\\SAM sam.hive")
        self.assertTrue(record["requires_admin"])
        self.assertEqual(record["risk"], "high")

    def test_an_explicit_admin_note_requires_admin(self):
        self.assertTrue(command_record("linux", "true", "Requires admin rights.")["requires_admin"])

    def test_credential_wording_flags_credential_store_access(self):
        record = command_record("windows", "cmdkey /list", "Enumerates stored credentials.")
        self.assertIn("credential_store_access", record["side_effects"])

    def test_session_disruption_is_flagged(self):
        record = command_record("windows", "rundll32.exe user32.dll,LockWorkStation")
        self.assertIn("interactive_session_disruption", record["side_effects"])
        self.assertEqual(record["risk"], "high")

    def test_cleanup_drives_both_rollback_and_the_cleanup_flag(self):
        record = command_record("linux", "touch /tmp/af", "", "rm -f /tmp/af")
        self.assertTrue(record["cleanup_required"])
        self.assertEqual(record["rollback"], "rm -f /tmp/af")

    def test_explicit_overrides_win_over_derived_values(self):
        record = command_record("windows", "whoami", "Read-only.",
                                risk="high", requires_admin=True, timeout_seconds=5,
                                side_effects=["custom"], acknowledgment_required=True)
        self.assertEqual(record["risk"], "high")
        self.assertTrue(record["requires_admin"])
        self.assertEqual(record["timeout_seconds"], 5)
        self.assertEqual(record["side_effects"], ["custom"])

    def test_classification_is_case_insensitive(self):
        self.assertTrue(command_record("windows", "REG ADD HKCU\\Software\\X")["requires_network"] is False)
        self.assertIn("changes_local_state", command_record("windows", "REG ADD HKCU\\Software\\X")["side_effects"])
        self.assertTrue(command_record("windows", "Invoke-WebRequest HTTPS://EXAMPLE.COM")["requires_network"])

    def test_a_registered_exercise_has_specific_telemetry_and_receipt_metadata(self):
        record = technique_exercise_record("T1110", {"platform": "windows"})
        self.assertEqual(record["command"], "python -m backend.lab_exercises T1110")
        self.assertIn("Five loopback HTTP 401 authentication failures", record["expected_telemetry"])
        self.assertEqual(record["network_targets"], ["127.0.0.1"])
        self.assertTrue(record["acknowledgment_required"])
        self.assertEqual(record["exercise_kind"], "technique_relevant_bounded")
        self.assertEqual(record["fidelity"], "bounded_synthetic")
        self.assertEqual(record["evidence_source"], "self_reported_receipt")


class NetworkTargetTests(unittest.TestCase):
    def test_urls_are_extracted_and_deduplicated(self):
        self.assertEqual(
            _network_targets("curl https://example.com/a && curl https://example.com/b"),
            ["example.com"])

    def test_both_schemes_are_recognized(self):
        self.assertEqual(_network_targets("wget http://lab.test/x https://other.test/y"),
                         ["lab.test", "other.test"])

    def test_a_bare_example_host_is_still_reported(self):
        self.assertEqual(_network_targets("nslookup example.com"), ["example.com"])

    def test_a_command_without_a_target_reports_nothing(self):
        self.assertEqual(_network_targets("whoami"), [])


if __name__ == "__main__":
    unittest.main()
