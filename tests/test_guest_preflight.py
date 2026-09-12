import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('preflight', ROOT / 'scripts/guest_preflight.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class PreflightTests(unittest.TestCase):
    def findings(self, **changes):
        data = dict(bootargs_revision=3, bootargs_version=2,
                    firmware_string='synthetic-known', memory_map_keys=['SEPFW', 'TrustCache'],
                    cpu_names=['cpu0', 'cpu1'], boot_cpu='cpu0', selected_cpu='cpu0')
        data.update(changes)
        return {f['code']: f for f in m.diagnose(data, {'synthetic-known': 'REFERENCE'}, {1:256, 2:608, 3:1024})}

    def test_new_revision_blocked_before_silent_loader_fallthrough(self):
        self.assertEqual(self.findings(bootargs_revision=4)['bootargs']['state'], 'blocked')

    def test_known_revision_is_not_runtime_support(self):
        f = self.findings()
        self.assertEqual(f['bootargs']['state'], 'checked')
        self.assertEqual(f['runtime_contract']['state'], 'unknown')

    def test_unknown_firmware_does_not_fabricate_alias_or_block_boot(self):
        self.assertEqual(self.findings(firmware_string='mBoot-synthetic')['firmware']['state'], 'unknown')

    def test_missing_trustcache_detected(self):
        self.assertEqual(self.findings(memory_map_keys=['SEPFW'])['memory_map']['state'], 'blocked')

    def test_missing_metadata_never_means_pass(self):
        f = m.diagnose({}, {}, {1:256})
        self.assertTrue(all(x['state'] == 'unknown' for x in f))

    def test_single_core_must_keep_actual_boot_core(self):
        self.assertEqual(self.findings(selected_cpu='cpu1')['single_cpu']['state'], 'blocked')

    def test_multidigit_cpu_not_misencoded_as_two_cores(self):
        f = self.findings(cpu_names=['cpu10'], boot_cpu='cpu10', selected_cpu='cpu10')
        self.assertEqual(f['single_cpu']['state'], 'checked')

    def test_command_line_nul_boundary(self):
        self.assertEqual(self.findings(command_line='x'*1023)['command_line']['state'], 'checked')
        self.assertEqual(self.findings(command_line='x'*1024)['command_line']['state'], 'blocked')

    def test_command_line_not_ascii(self):
        self.assertEqual(self.findings(command_line='é')['command_line']['state'], 'blocked')

    def test_invalid_and_unapproved_metadata_rejected(self):
        for data in ({'serial_number':'not-allowed'}, {'bootargs_revision':True}, {'cpu_names':'cpu0'}, []):
            with self.subTest(data=data), self.assertRaises(ValueError):
                m.validate(data)

    def test_source_drift_is_not_silently_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'loader').write_text('changed')
            with patch.object(m.subprocess, 'check_output', return_value='pin'), self.assertRaisesRegex(ValueError, 'Source contract changed'):
                m.contract(Path(d), {'commit':'pin', 'files': {'loader': '0'*64}})

    def test_source_missing_fails_closed(self):
        with tempfile.TemporaryDirectory() as d, patch.object(m.subprocess, 'check_output', return_value='pin'), self.assertRaises(ValueError):
            m.contract(Path(d), {'commit':'pin', 'files': {'missing': '0'*64}})

    def test_other_commit_requires_reaudit(self):
        with patch.object(m.subprocess, 'check_output', return_value='other'), self.assertRaisesRegex(ValueError, 'commit differs'):
            m.contract(Path('.'), {'commit':'pin', 'files':{}})

if __name__ == '__main__':
    unittest.main()
