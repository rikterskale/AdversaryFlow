import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any

from backend import ability_model, content_pack
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
