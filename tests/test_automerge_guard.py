"""Exercise the trusted workflow's merge decisions without GitHub writes."""

import textwrap
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch


class AutoMergeGuardTests(unittest.TestCase):
    def setUp(self):
        workflow = Path(".github/workflows/automerge.yml").read_text(encoding="utf-8")
        code = workflow.split("python - <<'PY'\n", 1)[1].split("          PY\n", 1)[0]
        self.namespace: dict[str, Any] = {"__name__": "workflow_test"}
        exec(compile(textwrap.dedent(code), "automerge.yml", "exec"), self.namespace)
        self.pr = {"state": "OPEN", "isDraft": False, "headRefOid": "head", "baseRefName": "main"}
        self.runs: dict[str, list[dict[str, str | None]]] = {
            "ci.yml": [{"status": "completed", "conclusion": "success"}],
            "codeql.yml": [{"status": "completed", "conclusion": "success"}],
        }
        self.merge_base = "base"
        self.namespace["gh_json"] = self.api

    def api(self, *args):
        if args[0] == "pr":
            return self.pr
        if "/compare/" in args[1]:
            return {"merge_base_commit": {"sha": self.merge_base}}
        if args[1].endswith("/commits/main"):
            return {"sha": "base"}
        self.assertIn("event=pull_request&head_sha=head", args[1])
        workflow = args[1].split("/workflows/", 1)[1].split("/", 1)[0]
        return {"workflow_runs": self.runs[workflow]}

    def invoke(self, attempts=1):
        self.namespace["wait_and_merge"]("owner/repo", "https://github.com/owner/repo/pull/1", "head", attempts)

    def test_success_merges_only_the_checked_commit(self):
        with patch("subprocess.run") as merge:
            self.invoke()
        merge.assert_called_once_with([
            "gh", "pr", "merge", "--rebase", "--match-head-commit", "head",
            "https://github.com/owner/repo/pull/1",
        ], check=True)

    def test_missing_or_pending_runs_never_merge(self):
        for runs in ([], [{"status": "in_progress", "conclusion": None}]):
            with self.subTest(runs=runs), patch("subprocess.run") as merge:
                self.runs["codeql.yml"] = runs
                with self.assertRaisesRegex(SystemExit, "Timed out"):
                    self.invoke()
                merge.assert_not_called()

    def test_failed_cancelled_or_skipped_runs_never_merge(self):
        for workflow in self.runs:
            for conclusion in ("failure", "cancelled", "skipped"):
                with self.subTest(workflow=workflow, conclusion=conclusion), patch("subprocess.run") as merge:
                    self.runs[workflow] = [{"status": "completed", "conclusion": conclusion}]
                    with self.assertRaisesRegex(SystemExit, "did not succeed"):
                        self.invoke()
                    merge.assert_not_called()
            self.runs[workflow] = [{"status": "completed", "conclusion": "success"}]

    def test_updated_closed_or_drafted_pr_never_merges(self):
        for field, value in (("headRefOid", "new-head"), ("state", "CLOSED"),
                             ("isDraft", True), ("baseRefName", "other")):
            with self.subTest(field=field), patch("subprocess.run") as merge:
                original = self.pr[field]
                self.pr[field] = value
                self.invoke()
                merge.assert_not_called()
                self.pr[field] = original

    def test_stale_base_never_merges(self):
        self.merge_base = "old-base"
        with patch("subprocess.run") as merge, self.assertRaisesRegex(SystemExit, "Update the PR"):
            self.invoke()
        merge.assert_not_called()

    def test_waits_for_both_workflows_before_merging(self):
        self.runs["ci.yml"] = []

        def finish_checks(_seconds):
            self.runs["ci.yml"] = [{"status": "completed", "conclusion": "success"}]

        with patch("time.sleep", side_effect=finish_checks) as sleep, patch("subprocess.run") as merge:
            self.invoke(attempts=2)
        sleep.assert_called_once_with(30)
        merge.assert_called_once()

    def test_api_error_never_merges(self):
        self.namespace["gh_json"] = Mock(side_effect=RuntimeError("API unavailable"))
        with patch("subprocess.run") as merge, self.assertRaisesRegex(RuntimeError, "API unavailable"):
            self.invoke()
        merge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
