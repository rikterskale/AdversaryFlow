import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from backend import app as service
from backend import attack_data
from backend.intelligence_import import IntelligenceImportError, compare_techniques, import_structured_source
from tests.test_attack_data import stix_bundle


class IntelligenceImportTests(unittest.TestCase):
    def test_csv_prefers_the_canonical_column_over_generic_row_ids(self):
        result = import_structured_source("id,attack_id,technique_id,procedure\n42,T1033,T1059.004,Lab example\n", "csv")
        self.assertEqual(result["candidates"][0]["technique_id"], "T1059.004")
        self.assertEqual(result["candidates"][0]["review_status"], "needs_review")

    def test_navigator_omits_disabled_techniques_and_does_not_infer_confidence(self):
        result = import_structured_source(json.dumps({"name": "Lab layer", "techniques": [
            {"techniqueID": "T1033", "score": 100, "comment": "Observed identity check"},
            {"techniqueID": "T1059.004", "enabled": False},
        ]}), "json")
        self.assertEqual(len(result["candidates"]), 1)
        self.assertIsNone(result["candidates"][0]["confidence"])

    def test_stix_non_string_version_returns_a_validation_error(self):
        versions: list[Any] = [[], {}, "2.0", 2.1]
        for version in versions:
            with self.subTest(version=version), self.assertRaises(IntelligenceImportError):
                import_structured_source(json.dumps({"type": "bundle", "objects": [
                    {"type": "attack-pattern", "spec_version": version},
                ]}), "json")

    def test_source_urls_and_confidence_are_validated(self):
        for text in ("technique_id,source_url\nT1033,http://example.com\n",
                     "technique_id,confidence\nT1033,NaN\n"):
            with self.subTest(text=text), self.assertRaises(IntelligenceImportError):
                import_structured_source(text, "csv")

    def test_comparison_is_deterministic_and_deduplicated(self):
        self.assertEqual(compare_techniques(["T1033", "T1059.004", "T1033"], ["T1033", "T1082"]), {
            "report_only": ["T1059.004"], "attack_only": ["T1082"], "both": ["T1033"],
        })


class IntelligenceApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for context in (
            patch.dict(service.os.environ, {"ADVERSARYFLOW_ENGAGEMENT_DB": str(Path(directory.name) / "test.sqlite3")}),
            patch.object(service, "REMOTE_MODE", False),
            patch.dict(service._runtime, {"loading": False}),
            patch("backend.attack_data.load_bundle", return_value=stix_bundle()),
        ):
            context.start()
            self.addCleanup(context.stop)
        attack_data.clear_memory_cache()
        self.addCleanup(attack_data.clear_memory_cache)
        self.client = service.app.test_client()
        self.headers = {"X-AdversaryFlow-CSRF": service._csrf_token}

    def test_all_structured_formats_preview_known_and_unknown_mappings_without_persistence(self):
        navigator = {"name": "Fixture layer", "techniques": [{"techniqueID": "T1059.001"}, {"techniqueID": "T9999"}]}
        stix = {"type": "bundle", "objects": [
            {"type": "attack-pattern", "id": f"attack-pattern--{technique_id}", "spec_version": "2.1",
             "name": technique_id, "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}]}
            for technique_id in ("T1059.001", "T9999")
        ]}
        inputs = (("csv", "technique_id,procedure,evidence_quote\nT1059.001,Reviewed procedure,Observed quote\nT9999,Unknown,\n", "csv"),
                  ("json", json.dumps(navigator), "navigator_layer"), ("json", json.dumps(stix), "stix2_bundle"))
        for kind, raw, expected_kind in inputs:
            with self.subTest(kind=expected_kind), patch("urllib.request.urlopen", side_effect=AssertionError("Source URL must not be fetched")):
                response = self.client.post("/api/intelligence/import", query_string={
                    "actor_stix_id": "intrusion-set--zeta", "source_kind": kind, "domains": "enterprise",
                    "source_name": "Fixture source", "source_url": "https://example.org/evidence",
                }, data=raw.encode(), headers=self.headers)
                self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                preview = response.get_json()
                self.assertEqual(preview["source"]["kind"], expected_kind)
                self.assertEqual(preview["source"]["sha256"], hashlib.sha256(raw.encode()).hexdigest())
                self.assertEqual(preview["comparison"], {"both": ["T1059.001"], "attack_only": ["T1082"], "report_only": ["T9999"]})
                self.assertEqual(preview["actor"]["stix_id"], "intrusion-set--zeta")
                self.assertEqual(preview["data_version"], "enterprise:bundle--fixture")
                known, unknown = preview["candidates"]
                self.assertTrue(known["technique_known"])
                self.assertEqual(known["technique_name"], "PowerShell")
                self.assertEqual(known["review_status"], "needs_review")
                self.assertTrue(known["abilities"])
                self.assertTrue(all("command" not in ability for ability in known["abilities"]))
                self.assertFalse(unknown["technique_known"])
                self.assertEqual(unknown["catalog_source"], "unsupported")
                self.assertEqual(unknown["abilities"], [])
        self.assertEqual(self.client.get("/api/engagements").get_json()["engagements"], [])
        self.assertEqual(self.client.get("/api/audit-events").get_json()["event_count"], 0)

    def test_preview_refuses_missing_actor_invalid_source_unknown_actor_and_loading_feed(self):
        raw = b"technique_id\nT1059.001\n"
        for actor, kind, loading, expected in (("", "csv", False, 400), ("missing", "csv", False, 404),
                                                ("intrusion-set--zeta", "unsupported", False, 400),
                                                ("intrusion-set--zeta", "csv", True, 503)):
            with self.subTest(actor=actor, kind=kind, loading=loading), patch.dict(service._runtime, {"loading": loading}):
                response = self.client.post("/api/intelligence/import", query_string={"actor_stix_id": actor, "source_kind": kind},
                                            data=raw, headers=self.headers)
                self.assertEqual(response.status_code, expected, response.get_data(as_text=True))
