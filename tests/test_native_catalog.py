import subprocess
import unittest

from backend.command_catalog import CURATED
from backend.lab_exercises import PORTABLE_EXERCISE_IDS
from backend.native_catalog import NATIVE_RECIPES
from backend.platform_support import PORTABLE_GAPS


class NativeCatalogTests(unittest.TestCase):
    def test_every_pinned_applicable_gap_has_an_explicit_native_or_bounded_recipe(self):
        self.assertEqual(len(PORTABLE_GAPS), 229)
        self.assertEqual(set(PORTABLE_GAPS), set(NATIVE_RECIPES) | set(PORTABLE_EXERCISE_IDS))
        self.assertFalse(set(NATIVE_RECIPES) & set(PORTABLE_EXERCISE_IDS))
        for tid, platforms in PORTABLE_GAPS.items():
            for platform in platforms:
                with self.subTest(technique=tid, platform=platform):
                    records = [c for c in CURATED[tid] if c['platform']==platform]
                    self.assertTrue(records)
                    self.assertTrue(all(c['environment']=='endpoint' for c in records))
                    for command in records:
                        self.assertTrue(command['prerequisites'])
                        self.assertTrue(command['expected_telemetry'])
                        result = subprocess.run(['bash','-n','-c',command['command']],capture_output=True,text=True,timeout=5,check=False)
                        self.assertEqual(result.returncode,0,result.stderr)

    def test_bounded_alternatives_are_distinct_and_explicit_on_all_platforms(self):
        for tid in PORTABLE_EXERCISE_IDS:
            commands=[c for c in CURATED[tid] if c.get('exercise_kind')]
            self.assertEqual({c['platform'] for c in commands},{'windows','linux','macos'})
            for command in commands:
                self.assertEqual(command['fidelity'],'bounded_synthetic')
                self.assertIn('does not reproduce harmful OS behavior',command['note'])
                self.assertFalse(command['requires_admin'])
                self.assertTrue(command['required_tools'])

    def test_native_inspection_recipes_never_mutate_host_controls(self):
        for tid in NATIVE_RECIPES:
            for command in CURATED[tid]:
                if command['platform'] not in PORTABLE_GAPS[tid]:
                    continue
                self.assertFalse(command['requires_network'])
                self.assertFalse(command['requires_admin'])
                for forbidden in ('sudo ', 'systemctl stop', 'launchctl unload', 'rm -rf', 'chmod ', 'chown '):
                    self.assertNotIn(forbidden,command['command'])


if __name__=='__main__':
    unittest.main()
