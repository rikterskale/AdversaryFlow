"""User acceptance tests.

One test per row of the journey map in docs/USER_JOURNEY.md that can be
executed without human judgment and without a pre-seeded ATT&CK bundle. Test
names carry the journey id so a failure names the accepted behaviour it broke.

Rows whose success criterion depends on the live ATT&CK bundle or a running
server are executed from the terminal and recorded in docs/UAT_PLAN.md.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from backend import app as app_module
from backend import attack_data

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, cache_dir: str | None = None) -> subprocess.CompletedProcess:
    """Invoke the CLI entry point the console script wraps, in its own process."""
    env = dict(os.environ)
    env.pop("ADVERSARYFLOW_OFFLINE", None)
    if cache_dir:
        env["ADVERSARYFLOW_CACHE_DIR"] = cache_dir
    return subprocess.run(
        [sys.executable, "-m", "backend.app", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False,
    )


class UatIndex:
    """Deterministic stand-in for a loaded ATT&CK index."""

    domains: ClassVar[list] = ["enterprise"]
    data_version = "enterprise:bundle--uat"
    tactic_order: ClassVar[list] = ["execution", "impact"]
    tactic_titles: ClassVar[dict] = {"execution": "Execution", "impact": "Impact"}

    def list_actors(self):
        return [{
            "stix_id": "intrusion-set--uat", "attack_id": "G0001", "name": "UAT Actor",
            "type": "group", "aliases": ["Example"], "description": "Fixture",
            "technique_count": 2,
        }]

    def get_actor(self, stix_id):
        if stix_id != "intrusion-set--uat":
            return None
        return {
            "id": stix_id, "type": "intrusion-set", "name": "UAT Actor",
            "aliases": ["Example"], "description": "Fixture",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}],
        }

    def actor_techniques(self, stix_id):
        return [
            {"stix_id": "attack-pattern--a", "attack_id": "T1059.001", "name": "PowerShell",
             "description": "Fixture", "tactics": ["execution"], "platforms": ["Windows"],
             "is_subtechnique": True, "data_sources": [], "detection": "",
             "url": "https://attack.mitre.org/techniques/T1059/001/"},
            {"stix_id": "attack-pattern--b", "attack_id": "T1486", "name": "Data Encrypted for Impact",
             "description": "Fixture", "tactics": ["impact"], "platforms": ["Windows"],
             "is_subtechnique": False, "data_sources": [], "detection": "", "url": None},
        ]


class ServiceUatTests(unittest.TestCase):
    """Journey rows served over HTTP."""

    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        app_module._runtime.update(ready=False, loading=False, phase="not_started",
                                   error="ATT&CK data has not been loaded")
        app_module._last_refresh = 0
        self.client = app_module.app.test_client()
        self.csrf = {"X-AdversaryFlow-CSRF": app_module._csrf_token}

    # -- J5 / J6 / J7 -----------------------------------------------------
    def test_j05_the_wizard_page_is_served(self):
        response = self.client.get("/")
        try:
            self.assertEqual(response.status_code, 200)
            self.assertIn("AdversaryFlow — Adversary Emulation Planner",
                          response.get_data(as_text=True))
        finally:
            response.close()

    def test_j06_every_response_is_hardened(self):
        response = self.client.get("/api/session")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertTrue(response.headers["X-Request-ID"])

    def test_j07_a_session_token_is_issued(self):
        body = self.client.get("/api/session").get_json()
        self.assertTrue(body["csrf_token"])
        self.assertEqual(body["version"], app_module.__version__)

    # -- J8 / J9 ----------------------------------------------------------
    @patch("backend.app.attack_data.cache_status", return_value={"domains": {}})
    @patch("backend.app.attack_data.get_index", return_value=UatIndex())
    def test_j08_bootstrap_starts_and_reaches_ready(self, _index, _cache):
        started = self.client.post("/api/bootstrap", headers=self.csrf)
        self.assertIn(started.status_code, (200, 202))
        app_module._bootstrap_worker()
        polled = self.client.get("/api/bootstrap")
        self.assertTrue(polled.get_json()["runtime"]["ready"])

    @patch("backend.app.attack_data.loaded_index_status",
           return_value={"ready": False, "domain_sets": [], "data_versions": []})
    def test_j09_health_is_degraded_before_data_is_ready(self, _status):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "degraded")

    @patch("backend.app.attack_data.loaded_index_status",
           return_value={"ready": True, "domain_sets": [["enterprise"]], "data_versions": ["uat"]})
    def test_j09_health_is_ready_once_data_is_loaded(self, _status):
        app_module._runtime.update(ready=True, error=None)
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ready")

    # -- J12 / J16 --------------------------------------------------------
    @patch("backend.app.attack_data.get_index", return_value=UatIndex())
    def test_j12_actor_records_carry_the_published_contract(self, _index):
        response = self.client.get("/api/actors")
        self.assertEqual(response.status_code, 200)
        for actor in response.get_json()["actors"]:
            self.assertEqual(set(actor), {
                "stix_id", "attack_id", "name", "type", "aliases", "description",
                "technique_count"})
            self.assertIn(actor["type"], {"group", "campaign"})
            self.assertGreater(actor["technique_count"], 0)

    @patch("backend.app.attack_data.get_index", return_value=UatIndex())
    def test_j16_the_workflow_is_ordered_and_fully_commanded(self, _index):
        body = self.client.get("/api/workflow/intrusion-set--uat").get_json()
        self.assertEqual(set(body), {"actor", "summary", "kill_chain", "stages", "metadata"})
        self.assertEqual([stage["tactic"] for stage in body["stages"]], ["execution", "impact"])
        self.assertEqual(body["summary"]["total_techniques"], 2)
        self.assertEqual(body["summary"]["curated_commands"], 2)
        self.assertEqual(body["summary"]["fallback_commands"], 0)
        for stage in body["stages"]:
            for technique in stage["techniques"]:
                self.assertTrue(technique["commands"])
                self.assertIn(technique["command_source"], {"curated", "fallback"})

    # -- J40 / J41 / J42 --------------------------------------------------
    def test_j40_an_unknown_domain_is_rejected(self):
        response = self.client.get("/api/actors?domains=bogus")
        self.assertEqual(response.status_code, 400)
        body = response.get_json()
        self.assertEqual(body["error"], "bad_request")
        self.assertIn("bogus", body["message"])

    @patch("backend.app.attack_data.get_index", return_value=UatIndex())
    def test_j41_an_unknown_actor_is_rejected(self, _index):
        response = self.client.get("/api/workflow/intrusion-set--nope")
        self.assertEqual(response.status_code, 404)
        body = response.get_json()
        self.assertEqual(body["error"], "actor_not_found")
        self.assertIn("intrusion-set--nope", body["message"])
        self.assertEqual(body["version"], app_module.__version__)

    def test_j42_a_mutation_without_the_token_is_refused(self):
        response = self.client.post("/api/refresh")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "forbidden")

    # -- J43 / J44 --------------------------------------------------------
    def test_j43_a_rejected_refresh_does_not_wedge_the_endpoint(self):
        rejected = self.client.post("/api/refresh?domains=bogus", headers=self.csrf)
        self.assertEqual(rejected.status_code, 400)
        self.assertFalse(app_module._refresh_lock.locked())
        app_module._last_refresh = 0
        with patch("backend.app.attack_data.refresh_index", return_value=UatIndex()), \
                patch("backend.app.attack_data.cache_status", return_value={}):
            accepted = self.client.post("/api/refresh?domains=enterprise", headers=self.csrf)
        self.assertEqual(accepted.status_code, 200)

    def test_j44_refreshes_are_rate_limited(self):
        with patch("backend.app.attack_data.refresh_index", return_value=UatIndex()), \
                patch("backend.app.attack_data.cache_status", return_value={}):
            first = self.client.post("/api/refresh", headers=self.csrf)
            second = self.client.post("/api/refresh", headers=self.csrf)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.get_json()["error"], "refresh_rate_limited")

    # -- J47 --------------------------------------------------------------
    def test_j47_remote_mode_enforces_the_bearer_token(self):
        app_module.REMOTE_MODE = True
        app_module.API_TOKEN = "uat-secret"
        try:
            self.assertEqual(self.client.get("/api/session").status_code, 401)
            allowed = self.client.get("/api/session",
                                      headers={"Authorization": "Bearer uat-secret"})
            self.assertEqual(allowed.status_code, 200)
            wrong = self.client.get("/api/session",
                                    headers={"Authorization": "Bearer wrong"})
            self.assertEqual(wrong.status_code, 401)
        finally:
            app_module.REMOTE_MODE = False
            app_module.API_TOKEN = ""


class CommandLineUatTests(unittest.TestCase):
    """Journey rows an operator drives from a terminal."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = self.directory.name

    def test_j02_the_version_is_reported(self):
        result = run_cli("--version", cache_dir=self.cache)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"AdversaryFlow {app_module.__version__}")

    def test_j03_doctor_reports_a_healthy_install(self):
        result = run_cli("doctor", cache_dir=self.cache)
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["ok"])
        self.assertTrue(report["frontend_available"])
        self.assertTrue(report["cache_writable"])
        self.assertEqual(report["version"], app_module.__version__)
        self.assertTrue(all(report["dependencies"].values()))

    def test_j04_the_process_answers_liveness_before_attack_data_is_ready(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env = dict(os.environ)
        env.pop("ADVERSARYFLOW_OFFLINE", None)
        env["ADVERSARYFLOW_CACHE_DIR"] = self.cache
        process = subprocess.Popen(
            [sys.executable, "-m", "backend.app", "--host", "127.0.0.1", "--port", str(port),
             "--no-preload", "--offline"],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            body = None
            for _ in range(50):
                try:
                    with urllib.request.urlopen(f"{url}/api/live", timeout=1) as response:
                        body = json.loads(response.read().decode("utf-8"))
                        break
                except (urllib.error.URLError, TimeoutError, ConnectionError):
                    if process.poll() is not None:
                        self.fail(f"service exited {process.returncode}")
                    time.sleep(0.1)
            self.assertIsNotNone(body)
            self.assertEqual(body["status"], "live")
            self.assertEqual(body["version"], app_module.__version__)
            with urllib.request.urlopen(url, timeout=2) as homepage:
                html = homepage.read().decode("utf-8")
            self.assertIn("AdversaryFlow — Adversary Emulation Planner", html)
            try:
                with urllib.request.urlopen(f"{url}/api/health", timeout=2) as health:
                    self.fail(f"health should be degraded before ATT&CK data loads: {health.status}")
            except urllib.error.HTTPError as exc:
                try:
                    exc.read()
                finally:
                    exc.close()
                self.assertEqual(exc.code, 503)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def test_j45_a_non_loopback_bind_is_refused(self):
        result = run_cli("--host", "0.0.0.0", "--no-preload", cache_dir=self.cache)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Refusing a non-loopback bind without --allow-remote.", result.stdout)

    def test_j46_a_remote_bind_without_a_token_is_refused(self):
        result = run_cli("--host", "0.0.0.0", "--allow-remote", "--no-preload",
                         cache_dir=self.cache)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Refusing a non-loopback bind without --api-token", result.stdout)

    def test_j48_cache_status_reports_every_domain(self):
        result = run_cli("cache-status", cache_dir=self.cache)
        report = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(set(report["domains"]), {"enterprise", "ics", "mobile"})
        for domain in report["domains"].values():
            self.assertIn("path", domain)
            self.assertFalse(domain["exists"])

    def test_j49_cache_clear_requires_confirmation(self):
        result = run_cli("cache-clear", cache_dir=self.cache)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Refusing to clear the cache without --yes.", result.stdout)

    def test_j50_cache_clear_removes_only_adversaryflow_files(self):
        bundle = os.path.join(self.cache, "enterprise-attack.json")
        keep = os.path.join(self.cache, "operator-notes.txt")
        Path(bundle).write_text("{}", encoding="utf-8")
        Path(keep).write_text("keep me", encoding="utf-8")
        result = run_cli("cache-clear", "--yes", cache_dir=self.cache)
        removed = json.loads(result.stdout)["removed"]
        self.assertEqual(result.returncode, 0)
        self.assertIn(bundle, removed)
        self.assertFalse(os.path.exists(bundle))
        self.assertEqual(Path(keep).read_text(encoding="utf-8"), "keep me")

    def test_j51_an_unknown_cli_domain_is_refused(self):
        result = run_cli("cache-refresh", "--domains", "bogus", cache_dir=self.cache)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown ATT&CK domain(s): bogus", result.stdout)

    def test_j53_offline_without_a_cache_is_actionable(self):
        attack_data.configure_cache_dir(self.cache)
        attack_data.configure_offline(True)
        self.addCleanup(attack_data.configure_offline, False)
        self.addCleanup(attack_data.configure_cache_dir, attack_data.CACHE_DIR)
        with self.assertRaisesRegex(
                RuntimeError, r"offline mode requires a cached enterprise ATT&CK bundle at"):
            attack_data.load_bundle("enterprise")


class BoundaryUatTests(unittest.TestCase):
    """Boundary inputs the accepted behaviour depends on."""

    def setUp(self):
        app_module.app.config.update(TESTING=True)
        app_module.REMOTE_MODE = False
        app_module.API_TOKEN = ""
        app_module._runtime.update(ready=False, loading=False, phase="not_started")
        self.client = app_module.app.test_client()

    def test_an_empty_domain_parameter_falls_back_to_enterprise(self):
        with app_module.app.test_request_context("/api/actors?domains="):
            self.assertEqual(app_module._domains_from_request(), ["enterprise"])

    def test_a_whitespace_only_domain_list_falls_back_to_enterprise(self):
        with app_module.app.test_request_context("/api/actors?domains=%20,%20"):
            self.assertEqual(app_module._domains_from_request(), ["enterprise"])

    def test_all_three_domains_are_accepted_together(self):
        with app_module.app.test_request_context("/api/actors?domains=enterprise,ics,mobile"):
            self.assertEqual(app_module._domains_from_request(),
                             ["enterprise", "ics", "mobile"])

    def test_one_bad_domain_rejects_the_whole_request(self):
        response = self.client.get("/api/actors?domains=enterprise,bogus")
        self.assertEqual(response.status_code, 400)

    def test_an_oversized_request_body_is_refused(self):
        oversized = json.dumps({"domains": ["enterprise"], "padding": "x" * (17 * 1024)})
        self.assertGreater(len(oversized), app_module.app.config["MAX_CONTENT_LENGTH"])

        # An unauthenticated request is rejected before the body is ever read.
        unauthenticated = self.client.post("/api/refresh", data=oversized,
                                           content_type="application/json")
        self.assertEqual(unauthenticated.status_code, 403)

        app_module._last_refresh = 0
        refused = self.client.post(
            "/api/refresh", data=oversized,
            headers={"X-AdversaryFlow-CSRF": app_module._csrf_token,
                     "Content-Type": "application/json"})
        self.assertEqual(refused.status_code, 413)
        self.assertEqual(refused.get_json()["error"], "request_entity_too_large")

    def test_a_body_under_the_limit_is_accepted(self):
        app_module._last_refresh = 0
        with patch("backend.app.attack_data.refresh_index", return_value=UatIndex()), \
                patch("backend.app.attack_data.cache_status", return_value={}):
            response = self.client.post(
                "/api/refresh", data=json.dumps({"domains": ["enterprise"]}),
                headers={"X-AdversaryFlow-CSRF": app_module._csrf_token,
                         "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 200)

    def test_a_technique_with_no_curated_entry_still_returns_a_command(self):
        from backend import command_catalog
        result = command_catalog.get_commands("T9999", "Unreleased Technique", ["execution"])
        self.assertEqual(result["source"], "fallback")
        self.assertEqual(len(result["commands"]), 1)
        self.assertIn("T9999", result["commands"][0]["command"])

    def test_a_technique_with_no_tactic_still_returns_a_command(self):
        from backend import command_catalog
        result = command_catalog.get_commands("T9999", "Unreleased Technique", [])
        self.assertEqual(result["source"], "fallback")
        self.assertTrue(result["commands"][0]["command"])

    def test_every_catalog_command_declares_a_known_risk_rating(self):
        from backend import command_catalog
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                with self.subTest(technique_id=technique_id):
                    self.assertIn(command["risk"], {"low", "medium", "high"})
                    if command["risk"] in {"medium", "high"}:
                        self.assertTrue(command["acknowledgment_required"])


if __name__ == "__main__":
    unittest.main()
