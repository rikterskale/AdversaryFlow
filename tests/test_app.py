import unittest
from unittest.mock import patch

from backend import app as app_module


class FakeIndex:
    domains = ["enterprise"]
    data_version = "enterprise:bundle--test"
    tactic_order = ["execution"]
    tactic_titles = {"execution": "Execution"}

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

    @patch("backend.app.attack_data.get_index", side_effect=RuntimeError("fixture failure"))
    def test_api_exceptions_are_structured(self, _index):
        response = self.client.get("/api/actors")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["error"], "request failed")


if __name__ == "__main__":
    unittest.main()
