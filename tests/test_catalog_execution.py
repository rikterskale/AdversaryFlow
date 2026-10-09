import csv
import io
import unittest
from unittest.mock import patch

from backend import command_catalog
from backend.catalog_execution import identify_command
from backend.execution_kit import normalize_plan, rebind_to_catalog, render_plan_csv
from backend.reporting import build_report, render_html
from tests.test_execution_kit import plan_fixture


class CatalogExecutionTests(unittest.TestCase):
    def test_execution_metadata_survives_catalog_rebinding_reports_and_kit_csv(self):
        plan = plan_fixture('linux')
        plan['scope']['allow_network'] = True
        command = next(c for c in command_catalog.CURATED['T1059.009'] if c['platform']=='linux')
        technique = plan['stages'][0]['techniques'][0]
        technique.update(id='T1059.009', name='Cloud API', command=command)
        plan['scope']['command_selections'] = {'T1059.009': command['command_id']}
        rebound = rebind_to_catalog(plan)
        self.assertEqual(rebound['stages'][0]['techniques'][0]['command']['command_id'], command['command_id'])
        row = next(csv.DictReader(io.StringIO(render_plan_csv(normalize_plan(rebound)).decode())))
        self.assertEqual(row['environment'], 'cloud')
        self.assertEqual(row['required_tools'], 'az')
        self.assertIn('authorized tenant', row['required_credentials'])
        report = build_report(plan)
        self.assertEqual(report.techniques[0].command_id, command['command_id'])
        self.assertIn(b'Execution context', render_html(report))

    def test_rebinding_preserves_reviewed_variants_and_never_uses_unknown_ids(self):
        plan = plan_fixture('linux')
        first = identify_command({**plan['stages'][0]['techniques'][0]['command'], 'requires_network': True})
        second = identify_command({**first, 'requires_network': False, 'command': 'hostname'})
        tid = plan['stages'][0]['techniques'][0]['id']
        with patch.dict(command_catalog.CURATED, {tid: [first, second]}):
            self.assertEqual(rebind_to_catalog(plan)['stages'][0]['techniques'][0]['command']['command'], 'hostname')
            plan['scope']['command_selections'] = {tid: first['command_id']}
            self.assertFalse(rebind_to_catalog(plan)['stages'][0]['techniques'][0]['supported'])
            plan['scope']['allow_network'] = True
            self.assertEqual(rebind_to_catalog(plan)['stages'][0]['techniques'][0]['command']['command_id'], first['command_id'])
            plan['scope']['command_selections'][tid] = 'f'*64
            self.assertFalse(rebind_to_catalog(plan)['stages'][0]['techniques'][0]['supported'])
    def test_every_block_has_a_real_executor_and_stable_identity(self):
        identities = set()
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                with self.subTest(technique=technique_id, platform=command['platform']):
                    self.assertIn(command['platform'], {'windows', 'linux', 'macos'})
                    self.assertIn(command['environment'], {'endpoint', 'cloud', 'container', 'pre_compromise'})
                    self.assertEqual(identify_command(command), command)
                    self.assertEqual(len(command['command_id']), 64)
                    identities.add(command['command_id'])
        self.assertGreater(len(identities), 850)

    def test_migrated_environment_commands_declare_tools_credentials_and_network(self):
        for command in command_catalog.CURATED['T1059.009']:
            self.assertEqual(command['environment'], 'cloud')
            self.assertEqual(command['required_tools'], ['az'])
            self.assertTrue(command['required_credentials'])
            self.assertTrue(command['requires_network'])
            self.assertNotIn('2>nul', command['command'])
        for command in command_catalog.CURATED['T1651']:
            self.assertFalse(command['requires_network'])
            self.assertFalse(command['required_credentials'])

    def test_pre_compromise_is_planning_not_endpoint_attestation(self):
        commands = command_catalog.CURATED['T1595']
        self.assertEqual({c['platform'] for c in commands}, {'windows', 'linux', 'macos'})
        for command in commands:
            self.assertEqual(command['execution_role'], 'planning')
            self.assertEqual(command['fidelity'], 'lab_proxy')
            self.assertFalse(command['requires_network'])
            self.assertIn('loopback_network_activity', command['side_effects'])
            self.assertEqual(command['network_targets'], ['127.0.0.1'])

    def test_non_endpoint_network_records_require_explicit_credentials(self):
        for technique_id, commands in command_catalog.CURATED.items():
            for command in commands:
                if command.get('environment') in {'cloud', 'container'} and command['requires_network']:
                    with self.subTest(technique=technique_id, platform=command['platform']):
                        self.assertTrue(command['required_credentials'])

    def test_linux_container_inspection_is_not_relabelled_for_windows(self):
        self.assertEqual([c['platform'] for c in command_catalog.CURATED['T1611']], ['linux'])

    def test_certificate_proxy_has_scoped_automatic_cleanup(self):
        for command in command_catalog.CURATED['T1587.002']:
            self.assertIn('finally' if command['platform']=='windows' else 'trap', command['command'])
            self.assertEqual(command['fidelity'], 'lab_proxy')


if __name__ == '__main__':
    unittest.main()
