import unittest
import tempfile
import hashlib
import io
import json
from unittest.mock import patch

from backend import attack_data


def bundle(domain: str) -> dict:
    return {
        "id": f"bundle--{domain}",
        "objects": [
            {
                "id": f"intrusion-set--{domain}",
                "type": "intrusion-set",
                "name": domain.title(),
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": f"G-{domain}"}
                ],
            }
        ],
    }


class DomainIndexTests(unittest.TestCase):
    def setUp(self):
        attack_data.clear_memory_cache()
        attack_data.configure_offline(False)

    def tearDown(self):
        attack_data.configure_offline(False)

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_sets_have_independent_indexes(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        self.assertIsNot(enterprise, ics)
        self.assertEqual(enterprise.domains, ["enterprise"])
        self.assertEqual(ics.domains, ["ics"])
        self.assertEqual(enterprise.data_version, "enterprise:bundle--enterprise")
        self.assertEqual(ics.data_version, "ics:bundle--ics")

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_order_is_normalized_and_duplicates_are_removed(self, _load):
        first = attack_data.get_index(["enterprise", "enterprise", "ics"])
        second = attack_data.get_index(["enterprise", "ics"])

        self.assertIs(first, second)
        self.assertEqual(first.domains, ["enterprise", "ics"])

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_rebuild_replaces_only_requested_domain_set(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        rebuilt = attack_data.get_index(["ics"], rebuild=True)

        self.assertIsNot(ics, rebuilt)
        self.assertIs(enterprise, attack_data.get_index(["enterprise"]))

    @patch("backend.attack_data.os.path.exists", return_value=False)
    def test_offline_mode_reports_missing_cache(self, _exists):
        attack_data.configure_offline(True)
        with self.assertRaisesRegex(RuntimeError, "offline mode requires a cached enterprise"):
            attack_data.load_bundle("enterprise")

    def test_bundle_validation_rejects_unstructured_json(self):
        with self.assertRaisesRegex(ValueError, "not a STIX bundle"):
            attack_data._validate_bundle({"objects": []}, "enterprise")

    def test_cache_status_reports_known_domains(self):
        original = attack_data.CACHE_DIR
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            status = attack_data.cache_status()
            self.assertEqual(set(status["domains"]), set(attack_data.STIX_SOURCES))
            self.assertFalse(status["domains"]["enterprise"]["exists"])
        attack_data.configure_cache_dir(original)

    def test_download_validates_and_records_provenance(self):
        original = attack_data.CACHE_DIR
        payload = json.dumps({
            "type": "bundle", "id": "bundle--test",
            "objects": [{"type": "x-mitre-matrix", "id": "x-mitre-matrix--test", "tactic_refs": []}],
        }).encode()
        response = io.BytesIO(payload)
        response.headers = {"Content-Length": str(len(payload)), "ETag": '"fixture"'}
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            destination = attack_data._cache_path("enterprise")
            with patch("backend.attack_data.urllib.request.urlopen", return_value=response):
                metadata = attack_data._download("https://example.test/bundle.json", destination, "enterprise")
            self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(attack_data._load_validated(destination, "enterprise")["id"], "bundle--test")
            self.assertEqual(attack_data._read_metadata("enterprise")["etag"], '"fixture"')
        attack_data.configure_cache_dir(original)

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain, force_refresh=False: bundle(domain))
    def test_refresh_invalidates_derived_domain_combinations(self, _load):
        combined = attack_data.get_index(["enterprise", "ics"])
        refreshed = attack_data.refresh_index(["enterprise"])
        self.assertIsNot(combined, refreshed)
        self.assertIsNot(combined, attack_data.get_index(["enterprise", "ics"]))


if __name__ == "__main__":
    unittest.main()
