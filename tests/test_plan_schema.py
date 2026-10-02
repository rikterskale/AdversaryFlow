"""The published plan contracts are enforced at every API boundary."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from backend import app as service
from backend.execution_kit import ExecutionKitError, normalize_plan, rebind_to_catalog
from backend.plan_schema import _validators, validate_plan_document
from tests.test_execution_kit import plan_fixture


def versioned_plan(version: str) -> dict[str, Any]:
    document = plan_fixture()
    if version == "3.0":
        document.update(schema_version=version, procedures=[])
    return document


class PlanSchemaTests(unittest.TestCase):
    def test_both_versions_resolve_schemas_and_formats_offline(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected schema download")):
            for version in ("2.0", "3.0"):
                with self.subTest(version=version):
                    validate_plan_document(versioned_plan(version))
                    normalize_plan(versioned_plan(version))

    def test_required_and_unknown_fields_are_enforced_throughout_the_plan(self):
        schema = _validators()["2.0"].schema
        for version in ("2.0", "3.0"):
            original = versioned_plan(version)
            groups = [((), schema), (("actor",), schema["$defs"]["actor"]),
                      (("scope",), schema["$defs"]["scope"]),
                      (("execution_context",), schema["$defs"]["executionContext"]),
                      (("summary",), schema["$defs"]["summary"]),
                      (("stages", 0), schema["$defs"]["stage"]),
                      (("stages", 0, "techniques", 0), schema["$defs"]["technique"]),
                      (("stages", 0, "techniques", 0, "command"), schema["$defs"]["command"]),
                      (("stages", 0, "techniques", 0, "execution"), schema["$defs"]["execution"])]
            for path, contract in groups:
                for key in (*contract["required"], "unexpected"):
                    document = copy.deepcopy(original)
                    target: Any = document
                    for part in path:
                        target = target[part]
                    if key == "unexpected":
                        target[key] = True
                    else:
                        del target[key]
                    with self.subTest(version=version, path=path, key=key), self.assertRaises(ExecutionKitError):
                        normalize_plan(document)

    def test_schema3_procedure_dates_and_references_are_checked(self):
        plan = versioned_plan("3.0")
        plan["procedures"] = [{
            "candidate_id": "candidate-1", "actor_stix_id": plan["actor"]["stix_id"],
            "mapping_data_version": plan["data_version"], "technique_id": "T1059.004", "technique_name": "Unix Shell",
            "tactics": ["execution"], "platforms": ["Linux"], "source_kind": "csv", "source_name": "review.csv",
            "source_url": "https://example.org/evidence", "source_sha256": "a" * 64, "evidence_quote": "Reviewed evidence",
            "procedure": "Reviewed procedure", "confidence": 0.8, "review_status": "accepted", "reviewed_by": "Lab team",
            "reviewed_at": "2026-10-01T12:00:00Z", "accepted_by": "Lab team", "accepted_at": "2026-10-01T12:00:00Z",
        }]
        normalize_plan(plan)
        for field, value in (("reviewed_at", "yesterday"), ("accepted_at", "2026-10-01"),
                             ("source_url", "https://[invalid"), ("confidence", True), ("confidence", 1.1)):
            document = copy.deepcopy(plan)
            document["procedures"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ExecutionKitError):
                normalize_plan(document)

    def test_rebinding_does_not_erase_invalid_client_command_metadata(self):
        plan = plan_fixture()
        plan["stages"][0]["techniques"][0]["command"]["unexpected"] = "should be rejected"
        with self.assertRaisesRegex(ExecutionKitError, "additionalProperties"):
            rebind_to_catalog(plan)

    def test_stage_and_total_technique_limits_apply_to_both_versions(self):
        for version in ("2.0", "3.0"):
            document = versioned_plan(version)
            stage = document["stages"][0]
            technique = stage["techniques"][0]
            stage["techniques"] = [technique] * 2000
            document["stages"] = [stage, copy.deepcopy(stage)]
            validate_plan_document(document)
            document["stages"].append({"tactic": "discovery", "title": "Discovery", "techniques": [technique]})
            with self.subTest(version=version, limit="total"), self.assertRaisesRegex(ExecutionKitError, "4000-step"):
                normalize_plan(document)
            document["stages"] = [stage]
            stage["techniques"].append(technique)
            with self.subTest(version=version, limit="stage"), self.assertRaisesRegex(ExecutionKitError, "maxItems"):
                normalize_plan(document)
            stage["techniques"] = [technique]
            document["stages"] = [stage] * 33
            with self.subTest(version=version, limit="stages"), self.assertRaisesRegex(ExecutionKitError, "maxItems"):
                normalize_plan(document)


class PlanSchemaApiTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        environment = patch.dict(service.os.environ, {"ADVERSARYFLOW_ENGAGEMENT_DB": str(Path(directory.name) / "test.sqlite3")})
        environment.start()
        self.addCleanup(environment.stop)
        remote = patch.object(service, "REMOTE_MODE", False)
        remote.start()
        self.addCleanup(remote.stop)
        self.client = service.app.test_client()
        self.headers = {"X-AdversaryFlow-CSRF": service._csrf_token}

    def test_invalid_contract_is_rejected_before_save_or_any_export(self):
        mutations = [
            ("actor", "aliases", None), ("actor", "type", "malware"), ("actor", "technique_count", True),
            (None, "domains", ["invalid-domain"]), (None, "domains", ["enterprise", "enterprise"]),
            (None, "generated", "2026-02-30T12:00:00Z"), (None, "generated", "2026-10-01T12:00:00"),
            (None, "tool_version", ""), (None, "unknown", 1), ("summary", "runnable", -1),
            ("summary", "techniques", 4001), ("scope", "stages", ["execution", "execution"]),
            ("scope", "allow_admin", "false"),
        ]
        endpoints = ("/api/engagements", "/api/report/json", "/api/report/html", "/api/report/pdf",
                     "/api/execution-kit", "/api/playbook/atomic")
        for version in ("2.0", "3.0"):
            for group, key, value in mutations:
                document = versioned_plan(version)
                target = document if group is None else document[group]
                if value is None:
                    del target[key]
                else:
                    target[key] = value
                for endpoint in endpoints:
                    with self.subTest(version=version, group=group, key=key, endpoint=endpoint):
                        body = {"plan": document} if endpoint == "/api/engagements" else document
                        response = self.client.post(endpoint, json=body, headers=self.headers)
                        self.assertEqual(response.status_code, 400, response.get_data(as_text=True))
        self.assertEqual(self.client.get("/api/engagements").get_json()["engagements"], [])
        self.assertEqual(self.client.get("/api/audit-events").get_json()["event_count"], 0)

    def test_valid_plans_save_and_export_without_losing_source_fields(self):
        for version in ("2.0", "3.0"):
            with self.subTest(version=version):
                document = versioned_plan(version)
                response = self.client.post("/api/engagements", json={"plan": document}, headers=self.headers)
                self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
                saved = response.get_json()
                revision = self.client.get(f"/api/engagements/{saved['engagement_id']}/revisions/1").get_json()
                self.assertEqual(revision["plan"], document)
                exported = self.client.post("/api/report/json", json=document, headers=self.headers)
                self.assertEqual(exported.status_code, 200, exported.get_data(as_text=True))
                self.assertEqual(json.loads(exported.data), document)
