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

    def test_openapi_defines_mutation_security_responses(self):
        contract = Path("docs/openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("/api/session:", contract)
        self.assertIn("/api/bootstrap:", contract)
        self.assertIn('"403"', contract)


if __name__ == "__main__":
    unittest.main()
