"""Contracts for the Compose-first operator and architecture documentation."""

import unittest
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    readme: ClassVar[str]
    getting_started: ClassVar[str]
    architecture: ClassVar[str]
    exports: ClassVar[str]
    troubleshooting: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.getting_started = (ROOT / "docs" / "GETTING_STARTED.md").read_text(encoding="utf-8")
        cls.architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        cls.exports = (ROOT / "docs" / "EXPORTS.md").read_text(encoding="utf-8")
        cls.troubleshooting = (ROOT / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")

    def test_readme_leads_with_the_supported_compose_path(self) -> None:
        commands = (
            "git clone https://github.com/rikterskale/AdversaryFlow.git",
            "cd AdversaryFlow",
            "docker compose up",
        )
        positions = [self.readme.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("[Architecture](docs/ARCHITECTURE.md)", self.readme)
        self.assertIn("less than five minutes", self.readme)

    def test_getting_started_has_a_no_execution_five_minute_path(self) -> None:
        compose = self.getting_started.index("## Five-minute dry-run with Docker Compose")
        native = self.getting_started.index("## 1. Check the machine for a native install")
        self.assertLess(compose, native)
        section = " ".join(self.getting_started[compose:native].split())
        self.assertIn("docker compose up", section)
        self.assertIn("not select **Copy command**", section)
        self.assertIn("**PDF engagement report**", section)
        self.assertIn("**Schema-versioned JSON**", section)
        self.assertIn("`0` outcomes recorded", section)

    def test_architecture_preserves_the_planner_boundary(self) -> None:
        self.assertIn("it has no\ncode path that executes a catalog command", self.architecture)
        self.assertIn("React 18 and TypeScript SPA", self.architecture)
        self.assertIn("frontend/\n├── src/", self.architecture)
        self.assertIn("browser-supplied command bodies are discarded", self.architecture.lower())
        self.assertIn("loopback-only publication", self.architecture)

    def test_report_formats_and_json_authority_are_documented(self) -> None:
        self.assertIn("**PDF engagement report**", self.exports)
        self.assertIn("**HTML engagement report**", self.exports)
        self.assertIn("Reports omit command bodies", self.exports)
        self.assertIn("Sigma rule labels and HTTPS references", self.exports)
        self.assertIn("JSON remains the canonical machine-readable", self.exports)

    def test_troubleshooting_covers_compose_reports_and_diagnostics(self) -> None:
        self.assertIn("`docker compose up` exits or restarts repeatedly", self.troubleshooting)
        self.assertIn("HTML/PDF report download fails", self.troubleshooting)
        self.assertIn("`ATT&CK feed reachability` is `FAIL`", self.troubleshooting)

    def test_primary_cross_document_links_resolve(self) -> None:
        paths = (
            ROOT / "docs" / "ARCHITECTURE.md",
            ROOT / "docs" / "GETTING_STARTED.md",
            ROOT / "docs" / "EXPORTS.md",
            ROOT / "docs" / "OPERATIONS.md",
            ROOT / "docs" / "TROUBLESHOOTING.md",
            ROOT / "ACCEPTABLE_USE.md",
            ROOT / "docs" / "openapi.yaml",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path.is_file(), f"documented file does not exist: {path}")


if __name__ == "__main__":
    unittest.main()
