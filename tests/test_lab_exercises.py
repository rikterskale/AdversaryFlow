import hashlib
import json
import unittest

from backend.lab_exercises import SCENARIOS, TECHNIQUE_SCENARIOS, get_spec, run_exercise


class LabExerciseTests(unittest.TestCase):
    def test_all_146_techniques_have_a_declared_scenario(self):
        self.assertEqual(len(TECHNIQUE_SCENARIOS), 146)
        self.assertTrue(set(TECHNIQUE_SCENARIOS.values()).issubset(SCENARIOS))

    def test_every_exercise_runs_cleans_up_and_emits_a_valid_receipt(self):
        for technique_id in sorted(TECHNIQUE_SCENARIOS):
            with self.subTest(technique_id=technique_id):
                receipt = run_exercise(technique_id)
                digest = receipt.pop("receipt_sha256")
                canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
                self.assertEqual(digest, hashlib.sha256(canonical).hexdigest())
                self.assertEqual(receipt["technique_id"], technique_id)
                self.assertEqual(receipt["scenario"], get_spec(technique_id).scenario)
                self.assertEqual(receipt["status"], "passed", receipt["error"])
                self.assertEqual(receipt["exit_code"], 0)
                self.assertTrue(receipt["cleanup_verified"])
                self.assertTrue(receipt["events"])
                self.assertIn("self-reported", receipt["attestation"])

    def test_brute_force_exercise_generates_bounded_authentication_failures(self):
        event = run_exercise("T1110")["events"][0]
        self.assertEqual(event["event"], "authentication_failures")
        self.assertEqual(event["attempts"], 5)
        self.assertEqual(event["statuses"], [401] * 5)
        self.assertEqual(event["target"], "127.0.0.1")

    def test_multi_hop_proxy_uses_two_loopback_hops(self):
        event = run_exercise("T1090.003")["events"][0]
        self.assertEqual(event["event"], "loopback_proxy")
        self.assertEqual(event["hops"], 2)
        self.assertTrue(event["digest_match"])

    def test_password_cracking_compares_a_bounded_offline_candidate_set(self):
        event = run_exercise("T1110.002")["events"][0]
        self.assertEqual(event["event"], "offline_password_hash_comparison")
        self.assertEqual(event["attempts"], 5)
        self.assertEqual(event["matched_indexes"], [2])


if __name__ == "__main__":
    unittest.main()
