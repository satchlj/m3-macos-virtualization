import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from revalidate_phase53_descriptor_bind import revalidate


class DescriptorRevalidationTests(unittest.TestCase):
    def report(self):
        before = [
            {'hex': '00000b' + '00' * 13, 'type': 11},
            {'hex': '00001400030000000000000000000000', 'type': 20},
            {'hex': '00000b' + '00' * 13, 'type': 11},
        ]
        after = copy.deepcopy(before)
        after[1]['hex'] = '00001400030001000000000000000000'
        checks = {'descriptor': True, 'status_success': True,
                  'fte_center_unchanged': False}
        return {
            'run_id': 'run',
            'stop_reason':
                'phase53-descriptor-bind-caller-return-gate-rejected',
            'xnu_phase53_descriptor_bind': {'stages': [
                {'stage': 'pre-map-call', 'complete': True,
                 'slot_pa': '0x2000', 'expected_descriptor': '0x4003',
                 'frame_table': {'records': before}},
                {'stage': 'caller-return', 'complete': False,
                 'slot_pa': '0x2000', 'descriptor': '0x4003',
                 'checks': checks, 'frame_table_after': {'records': after}},
            ]},
        }

    def test_accepts_legacy_opaque_metadata_false_negative(self):
        result = revalidate(json.dumps(self.report()).encode())
        self.assertTrue(result['complete'])
        self.assertEqual(result['fte_center_changed_offsets'], [6])

    def test_rejects_generic_or_neighbor_change(self):
        for record, offset in ((1, 2), (0, 6)):
            with self.subTest(record=record, offset=offset):
                report = self.report()
                raw = bytearray.fromhex(report[
                    'xnu_phase53_descriptor_bind']['stages'][1][
                        'frame_table_after']['records'][record]['hex'])
                raw[offset] ^= 1
                report['xnu_phase53_descriptor_bind']['stages'][1][
                    'frame_table_after']['records'][record]['hex'] = raw.hex()
                self.assertFalse(revalidate(json.dumps(report).encode())[
                    'complete'])

    def test_rejects_unrelated_failed_check(self):
        report = self.report()
        report['xnu_phase53_descriptor_bind']['stages'][1]['checks'][
            'descriptor'] = False
        self.assertFalse(revalidate(json.dumps(report).encode())['complete'])


if __name__ == '__main__':
    unittest.main()
