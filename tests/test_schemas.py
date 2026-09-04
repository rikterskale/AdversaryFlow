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
        self.assertEqual(schema["properties"]["stages"]["maxItems"], 32)
        self.assertEqual(schema["$defs"]["stage"]["properties"]["techniques"]["maxItems"], 2000)
        self.assertEqual(schema["$defs"]["command"]["properties"]["command"]["maxLength"], 10000)
        execution = schema["$defs"]["execution"]["properties"]
        for field in ("run_id", "started_at", "completed_at", "exit_code", "stdout_sha256", "stderr_sha256", "receipt_sha256", "receipt_verified", "telemetry_refs", "evidence_source"):
            self.assertIn(field, execution)
        self.assertEqual(execution["receipt_sha256"]["pattern"], "^[a-fA-F0-9]{64}$")
        self.assertIn("siem_verified", execution["evidence_source"]["enum"])

    def test_openapi_defines_mutation_security_responses(self):
        contract = Path("docs/openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("/api/session:", contract)
        self.assertIn("/api/bootstrap:", contract)
        self.assertIn('"403"', contract)


if __name__ == "__main__":
    unittest.main()
