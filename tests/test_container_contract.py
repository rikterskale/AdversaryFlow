"""Static safety and reproducibility contracts for the Compose install path."""

import re
import unittest
from pathlib import Path
from typing import ClassVar

from backend import __version__


class ContainerContractTests(unittest.TestCase):
    dockerfile: ClassVar[str]
    compose: ClassVar[str]
    entrypoint: ClassVar[str]

    @classmethod
    def setUpClass(cls):
        cls.dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
        cls.compose = Path("docker-compose.yml").read_text(encoding="utf-8")
        cls.entrypoint = Path("docker/entrypoint.sh").read_text(encoding="utf-8")

    def test_base_image_and_runtime_are_reproducibly_pinned(self):
        self.assertRegex(
            self.dockerfile.splitlines()[0],
            r"^# syntax=docker/dockerfile:\d+\.\d+@sha256:[0-9a-f]{64}$",
        )
        image = re.search(r"ARG PYTHON_IMAGE=([^\s]+)", self.dockerfile)
        assert image is not None
        self.assertRegex(image.group(1), r"^python:\d+\.\d+\.\d+-slim-bookworm@sha256:[0-9a-f]{64}$")
        node_image = re.search(r"ARG NODE_IMAGE=([^\s]+)", self.dockerfile)
        assert node_image is not None
        self.assertRegex(node_image.group(1), r"^node:\d+\.\d+\.\d+-bookworm-slim@sha256:[0-9a-f]{64}$")
        self.assertGreaterEqual(self.dockerfile.count("FROM ${PYTHON_IMAGE}"), 2)
        self.assertIn("--require-hashes --requirement /tmp/requirements.lock", self.dockerfile)
        self.assertIn("--require-hashes --requirement requirements-build.lock", self.dockerfile)

    def test_container_builds_the_spa_from_the_locked_source(self):
        self.assertIn("FROM ${NODE_IMAGE} AS frontend-builder", self.dockerfile)
        self.assertIn("COPY package.json package-lock.json ./", self.dockerfile)
        self.assertIn("RUN npm ci --ignore-scripts", self.dockerfile)
        self.assertIn("RUN npm run build:frontend", self.dockerfile)
        for asset in ("index.html", "styles.css", "app.js", "favicon.svg"):
            self.assertIn(f"COPY --from=frontend-builder /build/frontend/{asset}", self.dockerfile)

    def test_container_tags_match_the_package_version(self):
        self.assertIn(f'org.opencontainers.image.version="{__version__}"', self.dockerfile)
        self.assertIn(f"image: adversaryflow:{__version__}", self.compose)

    def test_runtime_is_non_root_and_drops_privileges(self):
        self.assertIn("USER 10001:10001", self.dockerfile)
        self.assertIn("read_only: true", self.compose)
        self.assertIn("no-new-privileges:true", self.compose)
        self.assertRegex(self.compose, r"cap_drop:\s*\n\s*- ALL")

    def test_host_publication_is_loopback_only_and_cache_is_persistent(self):
        self.assertIn('ADVERSARYFLOW_BIND_ADDRESS: "${ADVERSARYFLOW_BIND_ADDRESS:-127.0.0.1}"', self.compose)
        self.assertIn(
            '"${ADVERSARYFLOW_BIND_ADDRESS:-127.0.0.1}:${ADVERSARYFLOW_PORT:-5000}:${ADVERSARYFLOW_PORT:-5000}"',
            self.compose,
        )
        self.assertIn(
            '"adversaryflow-stix-cache:${ADVERSARYFLOW_CACHE_DIR:-/var/lib/adversaryflow/cache}"',
            self.compose,
        )
        self.assertIn("name: adversaryflow-stix-cache", self.compose)

    def test_launcher_environment_is_passed_through_with_safe_defaults(self):
        expected = {
            'ADVERSARYFLOW_HOST: "${ADVERSARYFLOW_HOST:-0.0.0.0}"',
            'ADVERSARYFLOW_PORT: "${ADVERSARYFLOW_PORT:-5000}"',
            'ADVERSARYFLOW_CACHE_DIR: "${ADVERSARYFLOW_CACHE_DIR:-/var/lib/adversaryflow/cache}"',
            'ADVERSARYFLOW_OFFLINE: "${ADVERSARYFLOW_OFFLINE:-false}"',
            'ADVERSARYFLOW_API_TOKEN: "${ADVERSARYFLOW_API_TOKEN:-}"',
        }
        for setting in expected:
            with self.subTest(setting=setting):
                self.assertIn(setting, self.compose)

    def test_container_keeps_the_non_loopback_bearer_gate(self):
        self.assertIn("ADVERSARYFLOW_HOST=0.0.0.0", self.dockerfile)
        self.assertIn('"--allow-remote"', self.dockerfile)
        self.assertIn("ADVERSARYFLOW_API_TOKEN", self.entrypoint)
        self.assertIn("secrets.token_urlsafe(32)", self.entrypoint)
        self.assertIn("Refusing remote container publication", self.entrypoint)
        self.assertNotRegex(self.compose, r"ADVERSARYFLOW_API_TOKEN:\s*[A-Za-z0-9_-]{16,}")

    def test_healthcheck_uses_the_authenticated_readiness_endpoint(self):
        healthcheck = Path("docker/healthcheck.py").read_text(encoding="utf-8")
        self.assertIn("/api/health", healthcheck)
        self.assertIn('os.environ.get("ADVERSARYFLOW_PORT", "5000")', healthcheck)
        self.assertIn("Authorization", healthcheck)
        self.assertIn('document.get("ready") is True', healthcheck)

    def test_entrypoint_reports_unwritable_runtime_directories_cleanly(self):
        self.assertIn("cannot write its cache directory", self.entrypoint)
        self.assertIn("cannot write its runtime token directory", self.entrypoint)


if __name__ == "__main__":
    unittest.main()
