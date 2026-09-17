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
        self.assertGreaterEqual(self.dockerfile.count("FROM ${PYTHON_IMAGE}"), 2)
        self.assertIn("--require-hashes --requirement requirements.lock", self.dockerfile)
        self.assertIn("--require-hashes --requirement requirements-build.lock", self.dockerfile)

    def test_container_tags_match_the_package_version(self):
        self.assertIn(f'org.opencontainers.image.version="{__version__}"', self.dockerfile)
        self.assertIn(f"image: adversaryflow:{__version__}", self.compose)

    def test_runtime_is_non_root_and_drops_privileges(self):
        self.assertIn("USER 10001:10001", self.dockerfile)
        self.assertIn("read_only: true", self.compose)
        self.assertIn("no-new-privileges:true", self.compose)
        self.assertRegex(self.compose, r"cap_drop:\s*\n\s*- ALL")

    def test_host_publication_is_loopback_only_and_cache_is_persistent(self):
        self.assertIn('"127.0.0.1:${ADVERSARYFLOW_PORT:-5000}:5000"', self.compose)
        self.assertIn("adversaryflow-stix-cache:/var/lib/adversaryflow/cache", self.compose)
        self.assertIn("name: adversaryflow-stix-cache", self.compose)

    def test_container_keeps_the_non_loopback_bearer_gate(self):
        self.assertIn('"--host", "0.0.0.0"', self.dockerfile)
        self.assertIn('"--allow-remote"', self.dockerfile)
        self.assertIn("ADVERSARYFLOW_API_TOKEN", self.entrypoint)
        self.assertIn("secrets.token_urlsafe(32)", self.entrypoint)
        self.assertNotRegex(self.compose, r"ADVERSARYFLOW_API_TOKEN:\s*[A-Za-z0-9_-]{16,}")

    def test_healthcheck_uses_the_authenticated_readiness_endpoint(self):
        healthcheck = Path("docker/healthcheck.py").read_text(encoding="utf-8")
        self.assertIn("/api/health", healthcheck)
        self.assertIn("Authorization", healthcheck)
        self.assertIn('document.get("ready") is True', healthcheck)


if __name__ == "__main__":
    unittest.main()
