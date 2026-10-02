import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from backend import ability_model, content_pack
from backend import app as service
from backend.command_catalog import get_commands


def reviewed_ability():
    commands = get_commands("T1059.004", "Unix Shell", ["execution"])["commands"]
    command = next(item for item in commands if item["platform"] == "linux")
    ability = ability_model.catalog_ability("T1059.004", command).to_dict()
    for field in ("requirements", "side_effects", "network_targets"):
        ability[field] = list(ability[field])
    ability.update(review_status="reviewed", content_source="fixture")
    return ability


class ContentPackValidationTests(unittest.TestCase):
    def test_ability_enum_fields_refuse_arrays_and_objects_cleanly(self):
        malformed: list[Any] = [[], {}]
        for field in ("platform", "executor", "fidelity", "safety_class"):
            for value in malformed:
                with self.subTest(field=field, value=value), self.assertRaises(content_pack.ContentPackError):
                    content_pack._normalize_ability({**reviewed_ability(), field: value}, require_identity=False)

    def test_detection_provider_refuses_an_array_cleanly(self):
        binding: dict[str, Any] = {"technique_id": "T1033", "provider": [], "rule_id": "fixture", "title": "Fixture",
                   "url": None, "content_sha256": "a" * 64, "reviewed_by": "Lab Team", "reviewed_at": "2026-09-30T12:00:00Z"}
        with self.assertRaises(content_pack.ContentPackError):
            content_pack._validate_binding(binding)

    def test_executor_must_match_the_destination_platform(self):
        for platform, executor in (("windows", "bash"), ("linux", "powershell"), ("macos", "cmd")):
            with self.subTest(platform=platform, executor=executor), self.assertRaisesRegex(content_pack.ContentPackError, "match its platform"):
                content_pack._normalize_ability({**reviewed_ability(), "platform": platform, "executor": executor}, require_identity=False)

    def test_pack_rejects_paths_outside_the_payload_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hostile.afpack"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../payload.json", "{}")
            with self.assertRaises(content_pack.ContentPackError):
                content_pack.verify_pack(path)


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "content-packs extra is not installed")
class SignedContentPackTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        private = self.root / "private.pem"
        public = self.root / "public.txt"
        content_pack._keygen(str(private), str(public))
        self.trust = json.dumps({"fixture-key": public.read_text().strip()})
        source = {"pack_id": "fixture", "pack_version": "1.0.0", "attack_version": "fixture-data",
                  "abilities": [reviewed_ability()], "detection_bindings": []}
        self.data = content_pack.sign_pack(source, private, "fixture-key")
        self.pack = self.root / "fixture.afpack"
        self.pack.write_bytes(self.data)

    def test_signed_pack_round_trips_with_pinned_identity(self):
        result = content_pack.verify_pack(self.pack, self.trust)
        self.assertEqual(result["ability_count"], 1)
        self.assertEqual(result["abilities"][0]["review_status"], "reviewed")
        self.assertEqual(result["attack_version"], "fixture-data")

    def test_cli_pack_drives_atomic_detection_reports_and_immutable_revision_pins(self):
        from tests.test_execution_kit import plan_fixture

        private, public = self.root / "cli.pem", self.root / "cli.txt"

        def cli(*args: Any) -> str:
            result = subprocess.run([sys.executable, "-m", "backend.content_pack", *map(str, args)],
                                    cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        cli("keygen", "--private-key", private, "--public-key", public)
        packs = self.root / "installed"
        packs.mkdir()
        source = {"pack_id": "integration", "pack_version": "1.0.0", "attack_version": "enterprise:bundle--fixture",
                  "abilities": [reviewed_ability()], "detection_bindings": [{
                      "technique_id": "T1059.004", "provider": "sigma", "rule_id": "integration-rule",
                      "title": "Reviewed detection", "url": "https://example.org/rules/integration",
                      "content_sha256": "a" * 64, "reviewed_by": "Lab Team", "reviewed_at": "2026-10-02T12:00:00Z",
                  }]}
        source_file = self.root / "source.json"
        source_file.write_text(json.dumps(source), encoding="utf-8")
        pack = packs / "integration.afpack"
        with patch.dict(os.environ, {
            "ADVERSARYFLOW_CONTENT_TRUSTED_KEYS": json.dumps({"integration-key": public.read_text().strip()}),
            "ADVERSARYFLOW_CONTENT_PACK_DIR": str(packs), "ADVERSARYFLOW_ENGAGEMENT_DB": str(self.root / "test.sqlite3"),
            "ADVERSARYFLOW_RUN_WEBHOOK_URL": "", "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": "",
        }), patch.object(service, "REMOTE_MODE", False):
            cli("sign", source_file, pack, "--private-key", private, "--key-id", "integration-key")
            verified = json.loads(cli("verify", pack))
            self.assertEqual(verified["ability_count"], 1)
            client = service.app.test_client()
            headers = {"X-AdversaryFlow-CSRF": service._csrf_token}
            self.assertEqual(client.get("/api/content-packs").get_json()["verified_detection_binding_count"], 1)
            plan = plan_fixture()
            atomic = client.post("/api/playbook/atomic", json=plan, headers=headers)
            self.assertEqual(atomic.status_code, 200, atomic.get_data(as_text=True) if atomic.status_code != 200 else "")
            with zipfile.ZipFile(io.BytesIO(atomic.data)) as archive:
                self.assertIn("atomics/T1059.004/T1059.004.yaml", archive.namelist())
            report = client.post("/api/report/html", json=plan, headers=headers)
            self.assertEqual(report.status_code, 200)
            self.assertIn(b"integration-rule", report.data)
            first = client.post("/api/engagements", json={"plan": plan}, headers=headers)
            self.assertEqual(first.status_code, 201)
            saved = first.get_json()
            pack.unlink()
            second = client.post("/api/engagements", json={"plan": plan, "engagement_id": saved["engagement_id"]}, headers=headers)
            self.assertEqual(second.status_code, 201)
            self.assertNotEqual(second.get_json()["content_pack_sha256"], saved["content_pack_sha256"])
            historical = client.get(f"/api/engagements/{saved['engagement_id']}/revisions/1").get_json()
            self.assertEqual(historical["content_pack_sha256"], saved["content_pack_sha256"])
            self.assertEqual(historical["plan"], plan)
            self.assertTrue(client.get("/api/audit-events").get_json()["chain_valid"])

    def test_untrusted_signer_is_refused(self):
        with self.assertRaisesRegex(content_pack.ContentPackError, "not trusted"):
            content_pack.verify_pack(self.pack, "{}")

    def test_payload_tampering_is_refused(self):
        with zipfile.ZipFile(io.BytesIO(self.data)) as original, zipfile.ZipFile(self.pack, "w") as tampered:
            for name in original.namelist():
                data = original.read(name)
                tampered.writestr(name, b"[]" if name == "abilities.json" else data)
        with self.assertRaisesRegex(content_pack.ContentPackError, "digest does not match"):
            content_pack.verify_pack(self.pack, self.trust)

    def test_non_ascii_payload_digest_is_refused_cleanly(self):
        with zipfile.ZipFile(io.BytesIO(self.data)) as original, zipfile.ZipFile(self.pack, "w") as altered:
            for name in original.namelist():
                data = original.read(name)
                if name == "manifest.json":
                    manifest = json.loads(data)
                    manifest["files"]["abilities.json"] = "é" * 64
                    data = json.dumps(manifest).encode()
                altered.writestr(name, data)
        with self.assertRaises(content_pack.ContentPackError):
            content_pack.verify_pack(self.pack, self.trust)
