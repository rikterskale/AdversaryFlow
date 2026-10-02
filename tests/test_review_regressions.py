"""Failure-path checks added during the October repository review."""
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from backend import app as service
from backend import execution_kit, intelligence_import
from backend.reporting import build_report
from tests.test_execution_kit import BASH, _bash_env, plan_fixture


class PlanValidationReviewTests(unittest.TestCase):
    def test_receipt_fields_must_match_every_occurrence_of_the_run(self):
        plan = plan_fixture("linux", duplicate=True)
        receipt = {"schema_version": "1.0", "technique_id": "T1059.004", "run_id": "fixture-run",
                   "status": "passed", "started_at": "2026-10-01T12:00:00Z", "completed_at": "2026-10-01T12:00:01Z",
                   "exit_code": 0, "cleanup_verified": True, "events": [], "scenario": "fixture",
                   "exercise_summary": "Fixture exercise", "expected_telemetry": "Fixture telemetry",
                   "duration_ms": 1000, "attestation": "Self-reported", "error": None}
        digest = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        receipt["receipt_sha256"] = digest
        plan.update(schema_version="3.0", procedures=[], receipts=[{
            "technique_id": "T1059.004", "run_id": "fixture-run", "receipt_sha256": digest, "receipt": receipt,
        }])
        for stage in plan["stages"]:
            stage["techniques"][0]["execution"] = {
                "outcome": "passed", "run_id": "fixture-run", "started_at": receipt["started_at"],
                "completed_at": receipt["completed_at"], "exit_code": 0, "cleanup_completed": True,
                "receipt_sha256": digest, "receipt_verified": True,
            }
        execution_kit.normalize_plan(plan)
        # The first occurrence used to be ignored when a later tactic repeated it.
        plan["stages"][0]["techniques"][0]["execution"]["outcome"] = "failed"
        with self.assertRaisesRegex(execution_kit.ExecutionKitError, "match a digest-verified"):
            execution_kit.normalize_plan(plan)

    def test_local_mode_refuses_dns_rebinding_hosts(self):
        with patch.object(service, "REMOTE_MODE", False):
            client = service.app.test_client()
            for host in ("attacker.example", "localhost.attacker.example", "192.168.1.1"):
                with self.subTest(host=host):
                    self.assertEqual(client.get("/api/session", base_url=f"http://{host}:5000").status_code, 403)
                    self.assertEqual(client.get("/", base_url=f"http://{host}:5000").status_code, 403)
            for host in ("localhost", "127.0.0.1", "[::1]"):
                self.assertEqual(client.get("/api/session", base_url=f"http://{host}:5000").status_code, 200)
        with patch.object(service, "REMOTE_MODE", True), patch.object(service, "API_TOKEN", "fixture-token"):
            self.assertEqual(service.app.test_client().get("/api/session", base_url="https://planner.example", headers={"Authorization": "Bearer fixture-token"}).status_code, 200)

    def test_malformed_report_url_does_not_crash_report_generation(self):
        plan = plan_fixture("linux")
        plan["stages"][0]["techniques"][0]["url"] = "https://[invalid"
        with self.assertRaisesRegex(ValueError, "url.*format"):
            build_report(plan)

    def test_unhashable_schema_values_are_validation_errors(self):
        invalid_values: tuple[Any, ...] = ([], {})
        for value in invalid_values:
            plan = plan_fixture()
            plan["schema_version"] = value
            with self.subTest(value=value), self.assertRaises(execution_kit.ExecutionKitError):
                execution_kit.normalize_plan(plan)

    def test_malformed_evidence_is_refused_before_persistence(self):
        invalid: dict[str, Any] = {
            "outcome": [], "detection_result": {}, "evidence_source": [],
            "telemetry_refs": [None], "run_id": [], "exit_code": True,
            "started_at": "2026-10-01", "receipt_verified": "true",
        }
        for field, value in invalid.items():
            plan = plan_fixture()
            plan["stages"][0]["techniques"][0]["execution"] = {"outcome": "not_run", field: value}
            with self.subTest(field=field), self.assertRaises(execution_kit.ExecutionKitError):
                execution_kit.normalize_plan(plan)

    def test_non_finite_and_invalid_unicode_values_are_refused(self):
        for value in (float("nan"), float("inf"), "\ud800"):
            plan = plan_fixture()
            plan["actor"]["description"] = value
            with self.subTest(value=repr(value)), self.assertRaises(execution_kit.ExecutionKitError):
                execution_kit.normalize_plan(plan)

    def test_import_handles_invalid_unicode_and_reference_shapes(self):
        inputs = [
            {"techniques": [{"techniqueID": "T1033", "comment": "\ud800"}]},
            {"type": "bundle", "objects": [{"type": "attack-pattern", "external_references": [{"source_name": [], "external_id": "T1033"}]}]},
        ]
        for value in inputs:
            with self.subTest(value=repr(value)), self.assertRaises(intelligence_import.IntelligenceImportError):
                intelligence_import.import_structured_source(json.dumps(value), "json")

    def test_non_ascii_authentication_headers_are_denied_cleanly(self):
        client = service.app.test_client()
        with patch.object(service, "REMOTE_MODE", True), patch.object(service, "API_TOKEN", "fixture"):
            response = client.get("/api/session", headers={"Authorization": "Bearer café"})
        self.assertEqual(response.status_code, 401)
        response = client.post("/api/refresh", headers={"X-AdversaryFlow-CSRF": "café"})
        self.assertEqual(response.status_code, 403)

    def test_atomic_backlog_failure_returns_a_service_error(self):
        client = service.app.test_client()
        token = client.get("/api/session").get_json()["csrf_token"]
        with patch("backend.app.engagement_store.upsert_ability_gaps", side_effect=service.engagement_store.EngagementStoreError("Store capacity reached")):
            response = client.post("/api/playbook/atomic", json=plan_fixture(), headers={"X-AdversaryFlow-CSRF": token})
        self.assertEqual(response.status_code, 503)
        self.assertIn("Store capacity", response.get_json()["message"])


class RunnerInputReviewTests(unittest.TestCase):
    @unittest.skipUnless(BASH, "A working Bash runtime is required")
    def test_closed_input_aborts_and_preserves_executed_step_evidence(self):
        self._check_closed_input("linux")

    @unittest.skipUnless(os.name == "nt" and shutil.which("pwsh"), "Native Windows PowerShell requires a Windows host")
    def test_closed_windows_input_preserves_executed_step_evidence(self):
        self._check_closed_input("windows")

    def _check_closed_input(self, platform):
        with tempfile.TemporaryDirectory() as directory:
            command = "Write-Output 'fixture'" if platform == "windows" else "printf 'fixture\\n'"
            data, _ = execution_kit.archive_execution_kit(execution_kit.normalize_plan(plan_fixture(platform, command=command)))
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                archive.extractall(directory)
            suffix = "ps1" if platform == "windows" else "sh"
            script = next(Path(directory).rglob(f"*-execute.{suffix}"))
            args = ["pwsh", "-NoProfile", "-File", str(script)] if platform == "windows" else [BASH, str(script)]
            result = subprocess.run(args, input=b"\n\nY\nR\n", capture_output=True, timeout=60, check=False, env=_bash_env())
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            evidence = next(script.parent.glob("AdversaryFlow-results-*"))
            summary = json.loads((evidence / "execution-summary.json").read_text(encoding="utf-8-sig"))
            self.assertEqual(summary["status"], "aborted")
            self.assertEqual(summary["completed_steps"], 1)
            with (evidence / "execution-results.csv").open(encoding="utf-8-sig") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["assessment"], "not_assessed")
            self.assertEqual(row["exit_code"], "0")
            self.assertTrue((evidence / "SHA256SUMS").is_file())

    @unittest.skipUnless(BASH, "A working Bash runtime is required")
    def test_closed_edit_reason_input_cannot_run_an_unapproved_edit(self):
        with tempfile.TemporaryDirectory() as directory:
            plan = plan_fixture(command="printf 'fixture\\n'")
            data, _ = execution_kit.archive_execution_kit(execution_kit.normalize_plan(plan))
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                archive.extractall(directory)
            script = next(Path(directory).rglob("*-execute.sh"))
            result = subprocess.run([BASH, str(script)], input=b"\n\nY\nE\n", capture_output=True,
                                    timeout=60, check=False, env=_bash_env({"EDITOR": "true"}))
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            evidence = next(script.parent.glob("AdversaryFlow-results-*"))
            summary = json.loads((evidence / "execution-summary.json").read_text())
            self.assertEqual(summary["status"], "aborted")
            self.assertEqual(summary["completed_steps"], 0)
            self.assertEqual(list((evidence / "stdout").iterdir()), [])
