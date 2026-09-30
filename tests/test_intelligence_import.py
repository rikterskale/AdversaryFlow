import json
import unittest
from typing import Any

from backend.intelligence_import import IntelligenceImportError, compare_techniques, import_structured_source


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
