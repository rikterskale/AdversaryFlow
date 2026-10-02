"""Contracts for the beginner install route and architecture documentation."""

import unittest
from pathlib import Path
from typing import ClassVar

from backend import __version__

ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    readme: ClassVar[str]
    getting_started: ClassVar[str]
    install: ClassVar[str]
    architecture: ClassVar[str]
    exports: ClassVar[str]
    troubleshooting: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.getting_started = (ROOT / "docs" / "GETTING_STARTED.md").read_text(encoding="utf-8")
        cls.install = (ROOT / "docs" / "INSTALL.md").read_text(encoding="utf-8")
        cls.architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        cls.exports = (ROOT / "docs" / "EXPORTS.md").read_text(encoding="utf-8")
        cls.troubleshooting = (ROOT / "docs" / "TROUBLESHOOTING.md").read_text(encoding="utf-8")

    def test_readme_downloads_a_zip_before_starting_compose(self) -> None:
        commands = (
            "https://github.com/rikterskale/AdversaryFlow/archive/refs/heads/main.zip",
            "\ndocker version\n",
            "\ndocker compose version\n",
            "\ndocker compose up --build\n",
        )
        positions = [self.readme.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(self.readme.index("## Install and open"), self.readme.index("## Create your first plan"))
        install = self.readme[self.readme.index("## Install and open"):self.readme.index("## Create your first plan")]
        self.assertNotIn("git clone", install)
        self.assertIn("Connect securely", install)
        for name in ("Dockerfile", "docker-compose.yml", "run.ps1"):
            self.assertIn(name, install)
            self.assertTrue((ROOT / name).is_file())
        self.assertIn("[Architecture](docs/ARCHITECTURE.md)", self.readme)

    def test_first_plan_exports_before_any_exercise_is_run(self) -> None:
        section = " ".join(self.readme[self.readme.index("## Create your first plan"):self.readme.index("## Save and resume")].split())
        self.assertIn("**Not run**", section)
        self.assertIn("**Not assessed**", section)
        self.assertIn("**Save JSON plan**", section)
        self.assertIn("**Generate report**", section)
        self.assertIn("**PDF**", section)
        self.assertIn("`0` outcomes recorded", section)

    def test_getting_started_native_example_matches_package_version(self) -> None:
        self.assertIn(
            f"AdversaryFlow {__version__}: http://127.0.0.1:5000",
            self.getting_started,
        )
        self.assertIn("powershell -NoProfile -ExecutionPolicy Bypass -File .\\run.ps1", self.getting_started)
        self.assertIn("chmod +x run.sh install.sh", self.getting_started)

    def test_install_reference_documents_compose_configuration_and_recovery(self) -> None:
        for setting in (
            "ADVERSARYFLOW_BIND_ADDRESS",
            "ADVERSARYFLOW_HOST",
            "ADVERSARYFLOW_PORT",
            "ADVERSARYFLOW_CACHE_DIR",
            "ADVERSARYFLOW_OFFLINE",
            "ADVERSARYFLOW_API_TOKEN",
            "ADVERSARYFLOW_PUBLIC_URL",
        ):
            with self.subTest(setting=setting):
                self.assertIn(setting, self.install)
        for failure in (
            "Docker troubleshooting matrix",
            "Cannot connect to the Docker daemon",
            "port is already allocated",
            "raw.githubusercontent.com",
            "STIX cache integrity",
            "Cache disk space",
        ):
            with self.subTest(failure=failure):
                self.assertIn(failure, self.install)
        self.assertIn("docker compose exec adversaryflow adversaryflow doctor", self.install)
        self.assertIn("refuses a non-loopback", self.install)

    def test_architecture_preserves_the_planner_boundary(self) -> None:
        self.assertIn("it has no\ncode path that executes a catalog command", self.architecture)
        self.assertIn("React 19 and TypeScript SPA", self.architecture)
        self.assertIn("frontend/\n├── src/", self.architecture)
        self.assertIn("browser-supplied command bodies are discarded", self.architecture.lower())
        self.assertIn("loopback-only publication", self.architecture)
        self.assertIn("## Repository and deployment layout", self.architecture)
        self.assertIn("docker-compose.yml", self.architecture)
        self.assertIn("entrypoint.sh", self.architecture)

    def test_report_formats_and_json_authority_are_documented(self) -> None:
        self.assertIn("**Generate report**", self.exports)
        self.assertIn("sandboxed\npreview", self.exports)
        self.assertIn("accepts `html`, `pdf`,\nor `json`", self.exports)
        self.assertIn("Reports omit command bodies", self.exports)
        self.assertIn("Sigma rule labels and HTTPS references", self.exports)
        self.assertIn("The current command catalog does not declare a Sigma-reference field.", self.exports)
        self.assertIn("x_mitre_data_sources", self.exports)
        self.assertIn("x_mitre_detection", self.exports)
        self.assertIn("JSON remains the canonical machine-readable", self.exports)
        self.assertIn("self-reported\nreceipt", self.exports)
        self.assertIn("independently collected endpoint or SIEM telemetry", self.exports)
        self.assertIn("does not refresh ATT&CK data, search for rules, run a kit", self.exports)

    def test_troubleshooting_covers_compose_reports_and_diagnostics(self) -> None:
        self.assertIn("`docker compose up` exits or restarts repeatedly", self.troubleshooting)
        self.assertIn("Report preview shows **Report generation failed**", self.troubleshooting)
        self.assertIn("PDF or JSON download fails after the preview is ready", self.troubleshooting)
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
