import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from backend.lab_exercises import run_exercise
from backend.telemetry import (
    TECHNIQUE_ACCEPTANCE,
    collect_native,
    correlate,
    normalize_event,
    read_events,
    verify_receipt,
)


class TelemetryAcceptanceTests(unittest.TestCase):
    def test_all_146_exercises_have_explicit_acceptance_criteria(self):
        self.assertEqual(len(TECHNIQUE_ACCEPTANCE), 146)
        for technique_id, criteria in TECHNIQUE_ACCEPTANCE.items():
            with self.subTest(technique_id=technique_id):
                self.assertEqual(criteria.technique_id, technique_id)
                self.assertTrue(criteria.activity_event_types)
                self.assertGreaterEqual(criteria.minimum_activity_events, 1)
                self.assertEqual(len(criteria.requirements), 3)
                self.assertIn("not harmful", criteria.limitation)

    def test_valid_independent_brute_force_telemetry_passes(self):
        receipt = run_exercise("T1110")
        when = receipt["started_at"]
        host = "lab-host-1"
        events = [{
            "timestamp": when,
            "source": "endpoint",
            "event_id": "proc-42",
            "host": host,
            "event_type": "process_start",
            "message": f"adversaryflow-run-marker --run-id {receipt['run_id']} --technique-id T1110",
        }, {
            "timestamp": when,
            "source": "siem",
            "event_id": "auth-99",
            "host": host,
            "event_type": "authentication_failure",
            "message": "five rejected loopback authentications",
            "count": 5,
        }]
        result = correlate(receipt, events)
        self.assertTrue(result["passed"])
        self.assertEqual(result["marker_events"], 1)
        self.assertEqual(result["activity_events"], 5)
        self.assertEqual(result["telemetry_refs"], ["endpoint:proc-42", "siem:auth-99"])

    def test_receipt_events_cannot_satisfy_independent_evidence(self):
        receipt = run_exercise("T1110")
        with self.assertRaisesRegex(ValueError, "endpoint or siem"):
            correlate(receipt, [{
                "timestamp": receipt["started_at"],
                "source": "self_reported_receipt",
                "event_id": "fake",
                "event_type": "authentication_failure",
                "message": receipt["run_id"],
            }])

    def test_missing_activity_or_marker_fails(self):
        receipt = run_exercise("T1110.002")
        event = {
            "timestamp": receipt["started_at"],
            "source": "endpoint",
            "event_id": "hash-1",
            "host": "host-a",
            "event_type": "hash_operation",
            "message": "offline hash operation",
        }
        self.assertFalse(correlate(receipt, [event])["passed"])

    def test_an_activity_event_cannot_masquerade_as_the_process_marker(self):
        receipt = run_exercise("T1110.002")
        event = {
            "timestamp": receipt["started_at"],
            "source": "siem",
            "event_id": "hash-2",
            "host": "host-a",
            "event_type": "hash_operation",
            "message": f"{receipt['run_id']} T1110.002",
        }
        result = correlate(receipt, [event])
        self.assertFalse(result["passed"])
        self.assertEqual(result["marker_events"], 0)

    def test_events_outside_the_receipt_window_do_not_count(self):
        receipt = run_exercise("T1110.002")
        outside = (datetime.fromisoformat(receipt["completed_at"]) + timedelta(minutes=5)).isoformat()
        events = [{
            "timestamp": outside,
            "source": "endpoint",
            "event_id": "late",
            "host": "host-a",
            "event_type": "hash_operation",
            "message": f"{receipt['run_id']} T1110.002",
        }]
        result = correlate(receipt, events)
        self.assertFalse(result["passed"])
        self.assertEqual(result["marker_events"], 0)

    def test_modified_receipt_fails_digest_validation(self):
        receipt = run_exercise("T1110.002")
        self.assertTrue(verify_receipt(receipt))
        receipt["status"] = "failed"
        self.assertFalse(verify_receipt(receipt))

    def test_json_and_json_lines_exports_are_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "events.json"
            second = root / "events.jsonl"
            first.write_text(json.dumps({"events": [{"@timestamp": "2026-09-04T12:00:00Z", "source": "siem"}]}), encoding="utf-8")
            second.write_text(json.dumps({"timestamp": "2026-09-04T12:00:01+00:00", "source": "endpoint"}) + "\n", encoding="utf-8")
            events = read_events([first, second])
        self.assertEqual(len(events), 2)
        self.assertEqual({event["source"] for event in events}, {"endpoint", "siem"})

    @patch("backend.telemetry.subprocess.run")
    def test_linux_native_collection_is_read_only_and_normalized(self, run: Mock):
        run.return_value = Mock(
            returncode=0,
            stdout=json.dumps({"__REALTIME_TIMESTAMP": "unused", "timestamp": "2026-09-04T12:00:00Z", "_HOSTNAME": "lab"}) + "\n",
            stderr="",
        )
        events = collect_native("linux", "2026-09-04T11:59:00Z", "2026-09-04T12:01:00Z")
        command = run.call_args.args[0]
        self.assertEqual(command[0], "journalctl")
        self.assertNotIn("--vacuum", command)
        self.assertEqual(events[0]["host"], "lab")

    def test_native_collection_rejects_non_iso_timestamps(self):
        with self.assertRaisesRegex(ValueError, "ISO 8601"):
            collect_native("windows", "2026-09-04T12:00:00Z'; calc.exe; '", "2026-09-04T12:01:00Z")

    def test_normalization_rejects_non_independent_sources(self):
        with self.assertRaisesRegex(ValueError, "endpoint or siem"):
            normalize_event({"timestamp": "2026-09-04T12:00:00Z", "source": "receipt"})


if __name__ == "__main__":
    unittest.main()
