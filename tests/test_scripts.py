"""Cover for the release-gating scripts in scripts/."""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name: str):
    """Import a scripts/ module by path — the directory is not a package."""
    spec = importlib.util.spec_from_file_location(f"_af_{name}", ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:  # pragma: no cover - packaging error
        raise ImportError(f"could not load scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_sbom = load("build_sbom")
validate_release = load("validate_release")

LOCK = """\
# comment line
--hash=sha256:ignored
Flask==3.1.3 \\
    --hash=sha256:aaaa
blinker==1.9.0
Not A Requirement Line
waitress==3.0.2
"""


class BuildSbomTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "backend").mkdir()
        (self.root / "backend" / "__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
        (self.root / "requirements.lock").write_text(LOCK, encoding="utf-8")
        self.patcher = patch.object(build_sbom, "ROOT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def document(self) -> dict:
        self.assertEqual(build_sbom.main(), 0)
        return json.loads((self.root / "dist" / "adversaryflow.cdx.json").read_text(encoding="utf-8"))

    def test_it_emits_a_cyclonedx_document_for_the_project_version(self):
        document = self.document()
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.6")
        self.assertEqual(document["metadata"]["component"]["version"], "9.9.9")
        self.assertEqual(document["metadata"]["component"]["purl"], "pkg:pypi/adversaryflow@9.9.9")

    def test_only_pinned_requirement_lines_become_components(self):
        components = self.document()["components"]
        self.assertEqual([c["name"] for c in components], ["blinker", "Flask", "waitress"])
        self.assertEqual([c["version"] for c in components], ["1.9.0", "3.1.3", "3.0.2"])
        self.assertTrue(all(c["type"] == "library" for c in components))

    def test_purls_are_lowercased(self):
        flask = next(c for c in self.document()["components"] if c["name"] == "Flask")
        self.assertEqual(flask["purl"], "pkg:pypi/flask@3.1.3")

    def test_the_document_is_deterministic_for_an_unchanged_lock(self):
        self.assertEqual(self.document()["serialNumber"], self.document()["serialNumber"])

    def test_the_serial_number_changes_when_the_lock_changes(self):
        first = self.document()["serialNumber"]
        (self.root / "requirements.lock").write_text("Flask==3.1.4\n", encoding="utf-8")
        self.assertNotEqual(first, self.document()["serialNumber"])

    def test_a_missing_version_declaration_fails_the_build(self):
        (self.root / "backend" / "__init__.py").write_text("# no version here\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "Could not read backend.__version__"):
            build_sbom.main()

    def test_the_output_directory_is_created_on_demand(self):
        self.assertFalse((self.root / "dist").exists())
        self.document()
        self.assertTrue((self.root / "dist" / "adversaryflow.cdx.json").is_file())


class ProjectVersionTests(unittest.TestCase):
    def test_the_declared_version_is_read_from_the_package(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "backend").mkdir()
        (root / "backend" / "__init__.py").write_text(
            '"""doc."""\n\n__version__ = "4.5.6"\n', encoding="utf-8")
        with patch.object(build_sbom, "ROOT", root):
            self.assertEqual(build_sbom._project_version(), "4.5.6")


class ValidateReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "backend").mkdir()
        self.write_version("1.2.3")
        self.write_changelog("## 1.2.3 — 2026-01-01\n\n- Fixture release.\n")
        self.previous = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)

    def write_version(self, version: str) -> None:
        (self.root / "backend" / "__init__.py").write_text(
            f'"""pkg."""\n\n__version__ = "{version}"\n', encoding="utf-8")

    def write_changelog(self, body: str) -> None:
        (self.root / "CHANGELOG.md").write_text(f"# Changelog\n\n{body}", encoding="utf-8")

    def run_with(self, tag: str) -> int:
        with patch.object(sys, "argv", ["validate_release.py", "--tag", tag]):
            return validate_release.main()

    def test_a_matching_tag_version_and_changelog_pass(self):
        self.assertEqual(self.run_with("v1.2.3"), 0)

    def test_a_mismatched_tag_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "does not match package version"):
            self.run_with("v1.2.4")

    def test_a_tag_without_the_v_prefix_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "does not match package version"):
            self.run_with("1.2.3")

    def test_a_changelog_without_the_release_section_is_rejected(self):
        self.write_changelog("## 0.9.0 — 2025-01-01\n\n- Older release.\n")
        with self.assertRaisesRegex(SystemExit, "has no 1.2.3 release section"):
            self.run_with("v1.2.3")

    def test_a_prefix_only_changelog_match_is_rejected(self):
        self.write_changelog("## 1.2.30 — 2026-01-01\n\n- Different release.\n")
        with self.assertRaisesRegex(SystemExit, "has no 1.2.3 release section"):
            self.run_with("v1.2.3")

    def test_an_unreadable_version_is_rejected(self):
        (self.root / "backend" / "__init__.py").write_text("# no version\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "Could not read backend.__version__"):
            self.run_with("v1.2.3")

    def test_the_tag_argument_is_required(self):
        with patch.object(sys, "argv", ["validate_release.py"]), self.assertRaises(SystemExit):
            validate_release.main()


class ShippedReleaseArtifactsTests(unittest.TestCase):
    """The checked-in version, changelog, and OpenAPI document must agree."""

    def test_the_current_version_passes_its_own_release_gate(self):
        from backend import __version__
        with patch.object(sys, "argv", ["validate_release.py", "--tag", f"v{__version__}"]):
            self.assertEqual(validate_release.main(), 0)

    def test_the_openapi_document_declares_the_current_version(self):
        from backend import __version__
        contract = (ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8")
        self.assertIn(f"version: {__version__}", contract)


if __name__ == "__main__":
    unittest.main()
