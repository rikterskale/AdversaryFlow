import io
import json
import unittest
import zipfile
from unittest.mock import patch

from backend import ability_model, atomic_adapter, content_pack
from backend.command_catalog import get_commands
from tests.test_execution_kit import plan_fixture


class AtomicAdapterTests(unittest.TestCase):
    def signed_ability(self):
        command = get_commands("T1059.004", "Unix Shell", ["execution"])["commands"]
        command = next(item for item in command if item["platform"] == "linux")
        ability = ability_model.catalog_ability("T1059.004", command).to_dict()
        ability.update(review_status="reviewed", content_source="signed_fixture", procedure_candidate_ids=[])
        return content_pack.VerifiedAbility(ability, "fixture", "1.0.0", "fixture-key")

    def test_legacy_abilities_remain_in_review_backlog(self):
        with patch.object(content_pack, "installed_packs", return_value=([], {}, {})):
            archive, manifest = atomic_adapter.build_atomic_pack(plan_fixture(duplicate=True))
        self.assertEqual(manifest["summary"], {"included": 0, "gaps": 1})
        self.assertEqual(manifest["gaps"][0]["gap"], "not_accepted")
        with zipfile.ZipFile(io.BytesIO(archive)) as output:
            self.assertEqual(output.namelist(), ["adversaryflow-atomic-manifest.json"])

    def test_reviewed_multi_tactic_technique_has_one_zip_definition(self):
        with patch.object(content_pack, "installed_packs", return_value=([], {("T1059.004", "linux"): self.signed_ability()}, {})):
            archive, manifest = atomic_adapter.build_atomic_pack(plan_fixture(duplicate=True))
        self.assertEqual(manifest["summary"], {"included": 1, "gaps": 0})
        with zipfile.ZipFile(io.BytesIO(archive)) as output:
            self.assertEqual(len(output.namelist()), len(set(output.namelist())))
            self.assertIn("atomics/T1059.004/T1059.004.yaml", output.namelist())
            self.assertEqual(json.loads(output.read("adversaryflow-atomic-manifest.json")), manifest)

    def test_signed_ability_cannot_bypass_network_scope(self):
        signed = self.signed_ability()
        signed.ability["requires_network"] = True
        plan = plan_fixture()
        plan["scope"]["allow_network"] = False
        with patch.object(content_pack, "installed_packs", return_value=([], {("T1059.004", "linux"): signed}, {})):
            _, manifest = atomic_adapter.build_atomic_pack(plan)
        self.assertEqual(manifest["included"], [])
        self.assertEqual(manifest["gaps"][0]["gap"], "out_of_scope")

    def test_signed_ability_cannot_reenable_a_withheld_plan_step(self):
        plan = plan_fixture()
        plan["stages"][0]["techniques"][0]["supported"] = False
        with patch.object(content_pack, "installed_packs", return_value=([], {("T1059.004", "linux"): self.signed_ability()}, {})):
            _, manifest = atomic_adapter.build_atomic_pack(plan)
        self.assertEqual(manifest["included"], [])
        self.assertEqual(manifest["gaps"][0]["gap"], "out_of_scope")
