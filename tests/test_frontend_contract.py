import unittest
from pathlib import Path
from typing import ClassVar


class FrontendContractTests(unittest.TestCase):
    javascript: ClassVar[str]
    source: ClassVar[str]
    html: ClassVar[str]
    css: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.javascript = Path("frontend/app.js").read_text(encoding="utf-8")
        cls.html = Path("frontend/index.html").read_text(encoding="utf-8")
        cls.css = Path("frontend/styles.css").read_text(encoding="utf-8")
        cls.source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(Path("frontend/src").rglob("*"))
            if path.suffix in {".ts", ".tsx", ".css"}
        )

    def test_platform_selection_has_no_cross_os_fallback(self):
        self.assertIn("command.platform === scope.commandPlatform", self.source)
        self.assertNotIn('command.platform === "windows"', self.source)
        self.assertIn("unsupported: true", self.source)

    def test_run_state_is_versioned(self):
        self.assertIn('name: "adversaryflow-wizard-v3"', self.source)
        self.assertIn("workflow.metadata.data_version", self.source)
        self.assertIn("scope.commandPlatform", self.source)
        self.assertIn("evidenceKey", self.source)

    def test_confirmations_and_resume_are_in_app_controls(self):
        self.assertNotIn("window.confirm", self.source)
        self.assertIn('role="dialog"', self.source)
        self.assertIn('title="Start a new plan?"', self.source)
        self.assertIn('id="importPlan"', self.source)
        self.assertIn("Resume JSON plan", self.source)
        self.assertNotIn("startRecommended", self.source)
        self.assertNotIn("FEATURED", self.source)
        self.assertIn('title="How to use AdversaryFlow"', self.source)
        self.assertIn("Could not prepare ATT&CK data", self.source)
        self.assertIn('id="firstLabHint"', self.source)
        self.assertIn("bounded synthetic", self.source)
        self.assertIn("lab proxy", self.source)
        self.assertIn("firstLabCommand", self.source)
        self.assertIn("detectedPlatform", self.source)
        self.assertIn("Try this first", self.source)

    def test_domain_controls_are_wired(self):
        self.assertIn("data-domain={option.value}", self.source)
        self.assertIn("onDomainsChange(next)", self.source)

    def test_export_copy_does_not_claim_unimplemented_integrations(self):
        self.assertNotIn("VECTR/Caldera import", self.source)

    def test_public_copy_uses_lab_positioning(self):
        self.assertIn("authorized lab validation", self.html)
        self.assertIn("Planner, never executor", self.source)
        self.assertNotIn("harmless", (self.html + self.source).lower())
        self.assertNotIn("authorized purple-team", self.source.lower())
        self.assertIn("command_source", self.source)
        self.assertNotIn("benign_source", self.source)
        self.assertNotIn("benign_command", self.source)

    def test_accessibility_contracts_exist(self):
        self.assertIn('aria-live="polite"', self.source)
        self.assertIn('prefers-reduced-motion', self.css)
        self.assertIn('aria-pressed', self.source)
        self.assertIn('className="skip-link"', self.source)
        self.assertIn('href="#main-content"', self.source)
        self.assertIn("Skip to content", self.source)

    def test_refresh_invalidates_current_workflow(self):
        self.assertIn("resetAfterRefresh", self.source)
        self.assertIn("records: {}", self.source)
        self.assertIn('"X-AdversaryFlow-CSRF"', self.source)

    def test_execution_evidence_and_safety_are_visible(self):
        self.assertIn('evidence__outcome', self.source)
        self.assertIn('acknowledgment_required', self.source)
        self.assertIn('execution_context', self.source)
        self.assertIn('receipt_sha256', self.source)
        self.assertIn('telemetry_refs', self.source)
        self.assertIn('Verify and import receipt', self.source)
        self.assertIn('${comment} COMMAND:', self.source)
        self.assertIn("ATT&CK detection", self.source)
        self.assertIn("data_sources", self.source)
        self.assertIn("evidence__detection", self.source)
        self.assertIn("detection_result", self.source)
        self.assertIn("handleKeys", self.source)
        self.assertIn("ensureEvidenceKey", self.source)

    def test_portable_execution_kit_is_a_one_click_gui_export(self):
        self.assertIn('/api/execution-kit', self.source)
        self.assertIn("buildExportBundle", self.source)
        self.assertIn("Download ${platform} execution kit", self.source)

    def test_production_assets_are_emitted(self):
        self.assertIn('<div id="root"></div>', self.html)
        self.assertIn('src="/app.js"', self.html)
        self.assertGreater(len(self.javascript), 100_000)


if __name__ == "__main__":
    unittest.main()
