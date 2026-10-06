import copy
import io
import json
import unittest
from contextlib import closing
from unittest.mock import patch

import pypdfium2
from PIL import ImageChops
from pypdf import PdfReader

from backend import app as app_module
from backend import reporting
from backend.artifact_limits import PLAN_MAX_BYTES
from backend.execution_kit import normalize_plan
from tests.test_app import ApiContractTests
from tests.test_execution_kit import plan_fixture


class ArtifactBoundaryRegressions(ApiContractTests):
    def test_F03_http_exact_boundary_minus_equal_plus_one_is_consistent(self):
        document = plan_fixture("linux")
        raw = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-AdversaryFlow-CSRF": app_module._csrf_token}
        for route in ("/api/report/json", "/api/execution-kit", "/api/playbook/atomic"):
            for offset in (-1, 0, 1):
                with self.subTest(route=route, offset=offset), \
                        patch("backend.app.execution_kit.build_execution_kit", return_value=(b"zip", "fixture.zip")):
                    padded = raw + b" " * (PLAN_MAX_BYTES + offset - len(raw))
                    # Atomic may reject the catalog mapping, but it must not
                    # reject a within-boundary document as too large.
                    result = self.client.post(route, data=padded, headers=headers)
                    self.assertEqual(result.status_code == 413, offset == 1)
                    if route == "/api/report/json" and offset <= 0:
                        self.assertEqual(result.status_code, 200)
                        self.assertLessEqual(len(result.data), PLAN_MAX_BYTES)
                        self.assertEqual(json.loads(result.data), document)

    def test_F03_large_schema3_utf8_plan_is_valid_and_http_save_report_accept_it(self):
        document = plan_fixture("linux")
        document.update(schema_version="3.0", procedures=[])
        for index in range(1400):
            document["procedures"].append({
                "candidate_id": f"candidate-{index}", "actor_stix_id": document["actor"]["stix_id"],
                "mapping_data_version": "fixture", "technique_id": "T1059.004", "technique_name": "Unix Shell",
                "tactics": ["execution"], "platforms": ["Linux"], "source_kind": "csv", "source_name": "fixture.csv",
                "source_url": None, "source_sha256": "a" * 64, "evidence_quote": "\u674e" * 2000, "procedure": "x" * 2000,
                "confidence": 1, "review_status": "accepted", "reviewed_by": "Reviewer",
                "reviewed_at": "2026-10-06T20:00:00Z", "accepted_by": "Reviewer", "accepted_at": "2026-10-06T20:00:00Z",
            })
        raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
        self.assertGreater(len(raw), 5 * 1024 * 1024)
        self.assertLess(len(raw), PLAN_MAX_BYTES)
        normalize_plan(document, require_executable=False)
        headers = {"Content-Type": "application/json", "X-AdversaryFlow-CSRF": app_module._csrf_token}
        report = self.client.post("/api/report/json", data=raw, headers=headers)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(json.loads(report.data), document)
        saved = self.client.post("/api/engagements", data=b'{"plan":' + raw + b"}", headers=headers)
        self.assertEqual(saved.status_code, 201)
        saved_body = saved.get_json()
        assert isinstance(saved_body, dict)
        revision = self.client.get(f"/api/engagements/{saved_body['engagement_id']}/revisions/1")
        revision_body = revision.get_json()
        assert isinstance(revision_body, dict)
        self.assertEqual(revision_body["plan"]["procedures"], document["procedures"])


class EvidenceAndPdfRegressions(unittest.TestCase):
    def test_F11_skipped_is_reviewed_not_executed_with_occurrence_multiplicity(self):
        document = plan_fixture("linux", duplicate=True)
        for stage in document["stages"]:
            for technique in stage["techniques"]:
                technique["execution"] = {"outcome": "skipped"}
        report = reporting.build_report(document)
        self.assertEqual(report.recorded, 0)
        self.assertEqual(report.coverage.outcome_skipped, 2)
        mixed = copy.deepcopy(document)
        mixed["stages"][1]["techniques"][0] = copy.deepcopy(mixed["stages"][1]["techniques"][0])
        mixed["stages"][0]["techniques"][0]["execution"]["outcome"] = "failed"
        self.assertEqual(reporting.build_report(mixed).recorded, 1)

    def test_F13_actual_pdf_extracts_chinese_cyrillic_symbols_and_explicit_emoji_marker(self):
        document = plan_fixture("linux")
        document["execution_context"]["operator"] = "\u674e\u96f7"
        document["stages"][0]["techniques"][0]["execution"] = {
            "outcome": "passed", "notes": "\u041f\u0440\u0438\u0432\u0435\u0442 \u2211 \U0001f50d",
        }
        body = reporting.render_pdf(reporting.build_report(document))
        reader = PdfReader(io.BytesIO(body))
        extracted = "\n".join(page.extract_text() for page in reader.pages)
        for expected in ("\u674e\u96f7", "\u041f\u0440\u0438\u0432\u0435\u0442", "\u2211", "[U+1F50D]"):
            self.assertIn(expected, extracted)
        self.assertNotIn("??", extracted)
        self.assertIn(b"/FontFile2", body)
        self.assertIn(b"/ToUnicode", body)
        self.assertGreater(len(reader.pages), 1)
        # Rasterize the actual document offline, locate real glyph boxes, and
        # prove distinct Chinese glyphs render ink rather than blank/tofu.
        with closing(pypdfium2.PdfDocument(body)) as pdf, closing(pdf[0]) as page:
            text_page = page.get_textpage()
            text = text_page.get_text_range(0, text_page.count_chars())
            image = page.render(scale=3).to_pil().convert("RGB")
            crops = []
            for character in "\u674e\u96f7":
                index = text.index(character)
                left, bottom, right, top = text_page.get_charbox(index)
                crop = image.crop((int(left * 3), int((page.get_height() - top) * 3),
                                   int(right * 3) + 1, int((page.get_height() - bottom) * 3) + 1))
                self.assertIsNotNone(ImageChops.invert(crop).getbbox())
                crops.append(crop.resize((32, 32)).tobytes())
            self.assertNotEqual(crops[0], crops[1])
            text_page.close()


if __name__ == "__main__":
    unittest.main()
