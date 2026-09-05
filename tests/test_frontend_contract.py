import unittest
from pathlib import Path
from typing import ClassVar


class FrontendContractTests(unittest.TestCase):
    javascript: ClassVar[str]
    html: ClassVar[str]
    css: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.javascript = Path("frontend/app.js").read_text(encoding="utf-8")
        cls.html = Path("frontend/index.html").read_text(encoding="utf-8")
        cls.css = Path("frontend/styles.css").read_text(encoding="utf-8")

    def test_platform_selection_has_no_cross_os_fallback(self):
        self.assertNotIn('list.find(c => c.platform === "windows")', self.javascript)
        self.assertNotIn('list.find(c => c.platform === "pre")', self.javascript)
        self.assertIn('unsupported: true', self.javascript)

    def test_run_state_is_versioned(self):
        self.assertIn('af_run_v3_', self.javascript)
        self.assertIn('state.dataVersion', self.javascript)
        self.assertIn('state.scope.cmdPlatform', self.javascript)

    def test_domain_controls_are_wired(self):
        self.assertIn('id="domainFilter"', self.html)
        self.assertIn('domainQuery()', self.javascript)

    def test_export_copy_does_not_claim_unimplemented_integrations(self):
        self.assertNotIn("VECTR/Caldera import", self.html)

    def test_public_copy_uses_lab_positioning(self):
        self.assertIn("Development-lab ATT&amp;CK planner", self.html)
        self.assertNotIn("harmless", self.html.lower())
        self.assertNotIn("authorized purple-team", self.javascript.lower())
        self.assertIn("command_source", self.javascript)
        self.assertNotIn("benign_source", self.javascript)
        self.assertIn("command: t._cmd", self.javascript)
        self.assertNotIn("benign_command", self.javascript)

    def test_accessibility_contracts_exist(self):
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn('prefers-reduced-motion', self.css)
        self.assertIn('aria-pressed', self.javascript)

    def test_refresh_invalidates_current_workflow(self):
        self.assertIn('state.workflow = null; state.records = {};', self.javascript)
        self.assertIn('X-AdversaryFlow-CSRF', self.javascript)

    def test_execution_evidence_and_safety_are_visible(self):
        self.assertIn('evidence__outcome', self.javascript)
        self.assertIn('acknowledgment_required', self.javascript)
        self.assertIn('execution_context', self.javascript)
        self.assertIn('receipt_sha256', self.javascript)
        self.assertIn('telemetry_refs', self.javascript)
        self.assertIn('Verify and import receipt', self.javascript)
        self.assertIn('${comment} COMMAND:', self.javascript)

    def test_portable_execution_kit_is_a_one_click_gui_export(self):
        self.assertIn('data-export="kit"', self.html)
        self.assertIn('id="executionKitExport"', self.html)
        self.assertIn('/api/execution-kit', self.javascript)
        self.assertIn('buildExportObj(p)', self.javascript)
        self.assertIn('Download operator execution kit', self.html)


if __name__ == "__main__":
    unittest.main()
