import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from backend import attack_data, diagnostics


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.original_cache_dir = attack_data.CACHE_DIR
        self.original_offline = attack_data.OFFLINE
        self.addCleanup(attack_data.configure_cache_dir, self.original_cache_dir)
        self.addCleanup(attack_data.configure_offline, self.original_offline)

    def test_an_occupied_port_fails_with_an_actionable_fix(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            check = diagnostics._port_check("127.0.0.1", port, False)
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("--port", check["fix"])

    def test_the_running_service_port_is_reported_as_available(self):
        check = diagnostics._port_check("127.0.0.1", 5000, True)
        self.assertEqual(check["status"], "PASS")
        self.assertIn("listening", check["detail"])

    def test_docker_and_compose_versions_are_reported_together(self):
        engine = subprocess.CompletedProcess(["docker"], 0, "27.5.1\n", "")
        compose = subprocess.CompletedProcess(["docker", "compose"], 0, "2.32.4\n", "")
        with patch("backend.diagnostics.shutil.which", return_value="docker"), \
                patch("backend.diagnostics._run_version_command", side_effect=[engine, compose]):
            check = diagnostics._docker_check()
        self.assertEqual(check["status"], "PASS")
        self.assertIn("27.5.1", check["detail"])
        self.assertIn("2.32.4", check["detail"])

    def test_an_existing_stix_bundle_is_parsed_and_digest_checked(self):
        bundle = {
            "type": "bundle",
            "id": "bundle--fixture",
            "objects": [{"type": "x-mitre-matrix", "id": "x-mitre-matrix--fixture"}],
        }
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            Path(attack_data._cache_path("enterprise")).write_text(json.dumps(bundle), encoding="utf-8")
            check = diagnostics._cache_integrity_check()
        self.assertEqual(check["status"], "PASS")
        self.assertIn("enterprise", check["detail"])

    def test_a_corrupt_stix_bundle_fails_with_a_bounded_recovery_command(self):
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            Path(attack_data._cache_path("enterprise")).write_text("not-json", encoding="utf-8")
            check = diagnostics._cache_integrity_check()
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("cache-clear --yes", check["fix"])

    def test_offline_mode_reports_feed_reachability_as_an_advisory_failure(self):
        attack_data.configure_offline(True)
        check = diagnostics._network_check(0.01)
        self.assertEqual(check["status"], "FAIL")
        self.assertFalse(check["required"])
        self.assertIn("Offline mode", check["detail"])

    def test_the_official_attack_source_is_probed_without_downloading_a_bundle(self):
        response = MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        with patch("backend.diagnostics.urllib.request.urlopen", return_value=response) as opener:
            check = diagnostics._network_check(0.5)
        self.assertEqual(check["status"], "PASS")
        request = opener.call_args.args[0]
        self.assertEqual(request.get_method(), "HEAD")
        self.assertEqual(opener.call_args.kwargs["timeout"], 0.5)

    def test_low_cache_disk_space_fails_with_a_move_or_free_space_fix(self):
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            usage = SimpleNamespace(total=1024, used=1023, free=1)
            with patch("backend.diagnostics.shutil.disk_usage", return_value=usage):
                check = diagnostics._disk_space_check()
        self.assertEqual(check["status"], "FAIL")
        self.assertIn("256 MiB", check["fix"])

    def test_required_failures_control_the_exit_ready_summary(self):
        python = diagnostics._result("python", "Python", True, "ready", "none")
        frontend = diagnostics._result("frontend", "Frontend", True, "ready", "none")
        dependencies = diagnostics._result("dependencies", "Dependencies", True, "ready", "none")
        port = diagnostics._result("port", "Port", True, "ready", "none")
        writable = diagnostics._result("cache_writable", "Cache", True, "ready", "none")
        disk = diagnostics._result("disk_space", "Disk", True, "ready", "none")
        advisory = diagnostics._result("advisory", "Advisory", False, "missing", "install", required=False)
        required = diagnostics._result("required", "Required", False, "broken", "repair")
        with tempfile.TemporaryDirectory() as directory, \
                patch("backend.diagnostics._python_check", return_value=python), \
                patch("backend.diagnostics._docker_check", return_value=advisory), \
                patch("backend.diagnostics._frontend_check", return_value=frontend), \
                patch("backend.diagnostics._dependency_check", return_value=(dependencies, {"Flask": "3.1.3", "waitress": "3.0.2"})), \
                patch("backend.diagnostics._port_check", return_value=port), \
                patch("backend.diagnostics._cache_writable_check", return_value=(writable, True, None)), \
                patch("backend.diagnostics._cache_integrity_check", return_value=required), \
                patch("backend.diagnostics._disk_space_check", return_value=disk), \
                patch("backend.diagnostics._network_check", return_value=advisory):
            attack_data.configure_cache_dir(directory)
            report = diagnostics.collect_diagnostics(directory)
        self.assertFalse(report["ok"])
        self.assertEqual(report["summary"]["required_failed"], 1)
        self.assertTrue(all(check["status"] in {"PASS", "FAIL"} for check in report["checks"]))
        self.assertTrue(all(check["fix"] for check in report["checks"]))


if __name__ == "__main__":
    unittest.main()
