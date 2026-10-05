"""CodeQL analysis survives unavailable hosting, but not unexpected API errors."""

import subprocess
import textwrap
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


class CodeQLDeliveryTests(unittest.TestCase):
    def setUp(self):
        workflow = Path(".github/workflows/codeql.yml").read_text(encoding="utf-8")
        code = workflow.split("python - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
        self.namespace: dict[str, Any] = {"__name__": "workflow_test"}
        exec(compile(textwrap.dedent(code), "codeql.yml", "exec"), self.namespace)

    def invoke(self, status, stdout, stderr=""):
        response = subprocess.CompletedProcess([], status, stdout=stdout, stderr=stderr)
        with patch("subprocess.run", return_value=response):
            return self.namespace["detect_upload"]("owner/repo")

    def test_enabled_scanning_uploads_results(self):
        self.assertEqual(self.invoke(0, "[]"), "always")

    def test_disabled_scanning_preserves_offline_analysis(self):
        self.assertEqual(self.invoke(1, '{"message":"Code scanning is not enabled for this repository."}'), "never")

    def test_permission_error_is_not_treated_as_disabled_scanning(self):
        with self.assertRaisesRegex(SystemExit, "Resource not accessible"):
            self.invoke(1, '{"message":"Resource not accessible by integration"}')

    def test_invalid_api_response_fails(self):
        with self.assertRaises(ValueError):
            self.invoke(1, "", "Network unavailable")


if __name__ == "__main__":
    unittest.main()
