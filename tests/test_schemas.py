import json
import unittest
from pathlib import Path


class SchemaTests(unittest.TestCase):
    def test_export_schema_is_strict_and_versioned(self):
        schema = json.loads(Path("schemas/adversaryflow-plan.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], "2.0")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("execution_context", schema["required"])
        self.assertIn("execution", schema["$defs"]["technique"]["required"])
        self.assertIn("risk", schema["$defs"]["command"]["required"])
        self.assertEqual(schema["$defs"]["command"]["properties"]["fidelity"]["enum"],
                         ["direct", "bounded_synthetic", "lab_proxy"])
        self.assertIn("data_sources", schema["$defs"]["technique"]["properties"])
        self.assertIn("detection", schema["$defs"]["technique"]["properties"])
        self.assertEqual(schema["properties"]["stages"]["maxItems"], 32)
        self.assertEqual(schema["$defs"]["stage"]["properties"]["techniques"]["maxItems"], 2000)
        self.assertEqual(schema["$defs"]["command"]["properties"]["command"]["maxLength"], 10000)
        execution = schema["$defs"]["execution"]["properties"]
        for field in ("run_id", "started_at", "completed_at", "exit_code", "stdout_sha256", "stderr_sha256", "receipt_sha256", "receipt_verified", "telemetry_refs", "evidence_source"):
            self.assertIn(field, execution)
        self.assertEqual(execution["receipt_sha256"]["pattern"], "^[a-fA-F0-9]{64}$")
        self.assertIn("siem_verified", execution["evidence_source"]["enum"])
        self.assertEqual(execution["detection_result"]["enum"],
                         ["not_assessed", "alerted", "silent", "blocked", "not_instrumented"])
        acceptance = schema["$defs"]["telemetry_acceptance"]
        self.assertFalse(acceptance["additionalProperties"])
        self.assertIn("activity_event_types", acceptance["required"])

    def test_openapi_defines_mutation_security_responses(self):
        contract = Path("docs/openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("/api/session:", contract)
        self.assertIn("/api/bootstrap:", contract)
        self.assertIn('"403"', contract)

    def test_openapi_command_contract_matches_the_plan_schema(self):
        contract = Path("docs/openapi.yaml").read_text(encoding="utf-8")
        schema = json.loads(Path("schemas/adversaryflow-plan.schema.json").read_text(encoding="utf-8"))
        self.assertIn("fidelity: { enum: [direct, bounded_synthetic, lab_proxy] }", contract)
        self.assertIn("risk: { enum: [none, low, medium, high] }", contract)
        self.assertEqual(schema["$defs"]["command"]["properties"]["fidelity"]["enum"],
                         ["direct", "bounded_synthetic", "lab_proxy"])
        self.assertEqual(schema["$defs"]["command"]["properties"]["risk"]["enum"],
                         ["none", "low", "medium", "high"])

    def test_portable_execution_summary_schema_is_strict_and_cross_platform(self):
        schema = json.loads(Path("schemas/adversaryflow-execution.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.0")
        self.assertEqual(schema["properties"]["platform"]["enum"], ["windows", "linux", "macos"])
        self.assertFalse(schema["additionalProperties"])
        for field in ("plan_sha256", "csv_sha256", "events_file", "results_file", "report_file"):
            self.assertIn(field, schema["required"])


if __name__ == "__main__":
    unittest.main()
