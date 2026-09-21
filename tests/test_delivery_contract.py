"""Static contracts for reproducible frontend validation and packaging."""

import json
import re
import unittest
from pathlib import Path
from typing import ClassVar


class DeliveryContractTests(unittest.TestCase):
    package: ClassVar[dict]
    workflow: ClassVar[str]
    release_workflow: ClassVar[str]
    workflows: ClassVar[dict[str, str]]
    dockerfile: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        cls.package = json.loads(Path("package.json").read_text(encoding="utf-8"))
        cls.workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
        cls.release_workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
        cls.workflows = {
            path.name: path.read_text(encoding="utf-8")
            for path in Path(".github/workflows").glob("*.yml")
        }
        cls.dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    def test_linux_workflow_runners_are_pinned(self):
        for name, workflow in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertNotIn("ubuntu-latest", workflow)
                self.assertIn("ubuntu-24.04", workflow)

    def test_frontend_asset_freshness_has_a_named_gate(self):
        command = self.package["scripts"]["check:frontend-assets"]
        for asset in ("index.html", "styles.css", "app.js", "favicon.svg"):
            self.assertIn(f"frontend/{asset}", command)
        self.assertIn("git diff --exit-code", command)

    def test_browser_job_runs_all_frontend_checks_before_playwright(self):
        browser = self.workflow[
            self.workflow.index("  browser:"):self.workflow.index("  compose-smoke:")
        ]
        ordered = (
            "npm ci --ignore-scripts",
            "npm run check:frontend",
            "npm run check:frontend-assets",
            "npx playwright install --with-deps chromium",
            "npm run test:e2e",
        )
        positions = [browser.index(command) for command in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_python_distributions_are_built_from_fresh_frontend_assets(self):
        build = self.workflow[
            self.workflow.index("  build:"):self.workflow.index("  browser:")
        ]
        ordered = (
            'node-version: "24.15.0"',
            "npm ci --ignore-scripts",
            "npm run build:frontend",
            "npm run check:frontend-assets",
            "python -m build --no-isolation",
            "python scripts/verify_distribution_assets.py",
        )
        positions = [build.index(command) for command in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_container_and_distribution_builds_share_the_canonical_node_line(self):
        match = re.search(r"ARG NODE_IMAGE=node:(\d+\.\d+\.\d+)-", self.dockerfile)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), "24.15.0")
        self.assertIn("RUN npm run build:frontend", self.dockerfile)

    def test_release_revalidates_frontend_and_distribution_bytes(self):
        ordered = (
            'node-version: "24.15.0"',
            "npm ci --ignore-scripts",
            "npm run check:frontend",
            "npm run check:frontend-assets",
            "python -m unittest discover --verbose",
            "python -m build --no-isolation",
            "python scripts/verify_distribution_assets.py",
            "python scripts/build_sbom.py",
        )
        positions = [self.release_workflow.index(command) for command in ordered]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
