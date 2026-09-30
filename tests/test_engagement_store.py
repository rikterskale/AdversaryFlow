"""Persistence, transaction, and connection lifetime regression coverage."""
import copy
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

from backend import engagement_store as store
from tests.test_execution_kit import plan_fixture


class EngagementStoreTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / "engagements.sqlite3"
        environment = patch.dict(os.environ, {
            "ADVERSARYFLOW_ENGAGEMENT_DB": str(self.database),
            "ADVERSARYFLOW_CONTENT_PACK_DIR": "",
            "ADVERSARYFLOW_RUN_WEBHOOK_URL": "",
            "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": "",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def test_every_read_and_early_return_closes_its_connection(self):
        connections = []
        connect = store._connect

        def track():
            connection = connect()
            connections.append(connection)
            return connection

        with patch.object(store, "_connect", side_effect=track):
            saved = store.save_revision(plan_fixture())
            store.list_engagements()
            store.get_engagement(saved["engagement_id"])
            store.get_engagement("missing")
            store.get_revision(saved["engagement_id"], 1)
            store.get_revision("missing", 1)
            store.engagement_exists(saved["engagement_id"])
            store.revision_exists(saved["engagement_id"], 1)
            store.list_run_records(saved["engagement_id"])
            store.list_audit_events()
            store.list_ability_gaps()
            store.list_webhook_deliveries()
            store.claim_webhook_deliveries()
            self.assertIsNone(store.update_ability_gap("missing", owner=None, status="open"))
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_connection_setup_failure_closes_the_handle(self):
        connection = Mock()
        connection.execute.side_effect = sqlite3.OperationalError("fixture PRAGMA failure")
        with patch.object(store.sqlite3, "connect", return_value=connection), self.assertRaises(sqlite3.OperationalError):
            store._connect()
        connection.close.assert_called_once()

    def test_revisions_preserve_prior_plans_and_record_runs(self):
        original = plan_fixture()
        first = store.save_revision(original)
        updated = copy.deepcopy(original)
        updated["stages"][0]["techniques"][0]["execution"] = {
            "outcome": "passed", "run_id": "lab-run-1", "detection_result": "alerted",
            "telemetry_refs": ["siem:event-42"],
        }
        second = store.save_revision(updated, first["engagement_id"])
        self.assertEqual(second["revision"], 2)
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])
        revision = store.get_revision(first["engagement_id"], 1)
        assert revision is not None
        self.assertEqual(revision["plan"], original)
        runs = store.list_run_records(first["engagement_id"], 2)
        self.assertEqual(runs[0]["result"], "passed")
        self.assertEqual(runs[0]["telemetry_refs"], ["siem:event-42"])
        self.assertEqual(store.list_audit_events()["event_count"], 2)

    def test_failed_revision_rolls_back_plan_and_audit_together(self):
        first = store.save_revision(plan_fixture())
        with patch.object(store, "_insert_audit_event", side_effect=store.EngagementStoreError("fixture failure")), \
                self.assertRaises(store.EngagementStoreError):
            store.save_revision(plan_fixture(), first["engagement_id"])
        engagement = store.get_engagement(first["engagement_id"])
        assert engagement is not None
        self.assertEqual(len(engagement["revisions"]), 1)
        self.assertEqual(store.list_audit_events()["event_count"], 1)

    def test_concurrent_saves_assign_distinct_revisions(self):
        first = store.save_revision(plan_fixture())
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: store.save_revision(plan_fixture(), first["engagement_id"]), range(8)))
        self.assertEqual(sorted(item["revision"] for item in results), list(range(2, 10)))
        self.assertEqual(store.list_audit_events()["event_count"], 9)

    def test_revision_cannot_change_actor(self):
        plan = plan_fixture()
        first = store.save_revision(plan)
        plan["actor"]["attack_id"] = "G9999"
        with self.assertRaisesRegex(store.EngagementStoreError, "cannot change"):
            store.save_revision(plan, first["engagement_id"])
        engagement = store.get_engagement(first["engagement_id"])
        assert engagement is not None
        self.assertEqual(len(engagement["revisions"]), 1)

    def test_audit_tampering_is_detected_on_read_and_append(self):
        store.save_revision(plan_fixture())
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("UPDATE audit_events SET principal = 'tampered'")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(store.EngagementStoreError, "verification failed"):
            store.list_audit_events()
        with self.assertRaisesRegex(store.EngagementStoreError, "verification failed"):
            store.save_revision(plan_fixture())

    def test_regenerating_gaps_preserves_owner_and_status(self):
        gap = {"technique_id": "T1059.004", "platform": "linux", "gap": "not_accepted",
               "ability_id": "fixture", "procedure_candidate_ids": [], "reason": "Needs review"}
        saved = store.upsert_ability_gaps([gap])[0]
        store.update_ability_gap(saved["id"], owner="Purple Team", status="in_progress")
        again = store.upsert_ability_gaps([{**gap, "reason": "Still needs review"}])[0]
        self.assertEqual(again["id"], saved["id"])
        self.assertEqual(again["owner"], "Purple Team")
        self.assertEqual(again["status"], "in_progress")
        self.assertTrue(store.list_audit_events()["chain_valid"])

    def test_webhook_is_queued_leased_and_completed_without_network(self):
        plan = plan_fixture()
        plan["stages"][0]["techniques"][0]["execution"] = {"outcome": "passed", "run_id": "run-1"}
        with patch.dict(os.environ, {"ADVERSARYFLOW_RUN_WEBHOOK_URL": "https://example.invalid/events",
                                     "ADVERSARYFLOW_RUN_WEBHOOK_SECRET": "s" * 32}):
            store.save_revision(plan)
        deliveries = store.claim_webhook_deliveries()
        self.assertEqual(len(deliveries), 1)
        self.assertEqual(store.claim_webhook_deliveries(), [])
        self.assertEqual(deliveries[0]["payload"]["run"]["run_id"], "run-1")
        store.complete_webhook_delivery(deliveries[0]["delivery_id"], success=True)
        self.assertEqual(store.list_webhook_deliveries()[0]["status"], "delivered")


if __name__ == "__main__":
    unittest.main()
