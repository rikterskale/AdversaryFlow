import unittest
from unittest.mock import patch

from backend import attack_data


def bundle(domain: str) -> dict:
    return {
        "id": f"bundle--{domain}",
        "objects": [
            {
                "id": f"intrusion-set--{domain}",
                "type": "intrusion-set",
                "name": domain.title(),
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": f"G-{domain}"}
                ],
            }
        ],
    }


class DomainIndexTests(unittest.TestCase):
    def setUp(self):
        attack_data.clear_memory_cache()
        attack_data.configure_offline(False)

    def tearDown(self):
        attack_data.configure_offline(False)

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_sets_have_independent_indexes(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        self.assertIsNot(enterprise, ics)
        self.assertEqual(enterprise.domains, ["enterprise"])
        self.assertEqual(ics.domains, ["ics"])
        self.assertEqual(enterprise.data_version, "enterprise:bundle--enterprise")
        self.assertEqual(ics.data_version, "ics:bundle--ics")

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_domain_order_is_normalized_and_duplicates_are_removed(self, _load):
        first = attack_data.get_index(["enterprise", "enterprise", "ics"])
        second = attack_data.get_index(["enterprise", "ics"])

        self.assertIs(first, second)
        self.assertEqual(first.domains, ["enterprise", "ics"])

    @patch("backend.attack_data.load_bundle", side_effect=lambda domain: bundle(domain))
    def test_rebuild_replaces_only_requested_domain_set(self, _load):
        enterprise = attack_data.get_index(["enterprise"])
        ics = attack_data.get_index(["ics"])

        rebuilt = attack_data.get_index(["ics"], rebuild=True)

        self.assertIsNot(ics, rebuilt)
        self.assertIs(enterprise, attack_data.get_index(["enterprise"]))

    @patch("backend.attack_data.os.path.exists", return_value=False)
    def test_offline_mode_reports_missing_cache(self, _exists):
        attack_data.configure_offline(True)
        with self.assertRaisesRegex(RuntimeError, "offline mode requires a cached enterprise"):
            attack_data.load_bundle("enterprise")


if __name__ == "__main__":
    unittest.main()
