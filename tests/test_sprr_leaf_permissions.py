import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from sprr_leaf_permissions import main
from sprr_permissions import leaf_permissions

PPERM = 0x2020a52a302abaf5
UPERM = 0x2010002030100000


class SprrLeafCliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_json_output_matches_library_for_both_worlds(self):
        descriptor = 0x20000403 | (1 << 53) | (1 << 6)  # index 5
        for extra, world in (([], 'ordinary'), (['--world', 'guarded'], 'guarded')):
            status, out, err = self.run_cli([hex(descriptor), hex(PPERM), str(UPERM)]+extra)
            self.assertEqual((status, err), (0, ''))
            decoded = json.loads(out)
            expected = dict(descriptor=descriptor, pperm_el1=PPERM, uperm_el0=UPERM,
                            **leaf_permissions(descriptor, PPERM, UPERM, world))
            self.assertEqual(decoded, expected)
            self.assertEqual(decoded['index'], 5)
        self.assertEqual(decoded['world'], 'guarded')

    def test_invalid_descriptor_and_world_fail_without_json(self):
        status, out, err = self.run_cli(['0x402', hex(PPERM), hex(UPERM)])
        self.assertEqual((status, out), (2, ''))
        self.assertIn('not valid', err)
        with self.assertRaises(SystemExit):
            self.run_cli(['0x403', '1', '2', '--world', 'other'])
        with self.assertRaises(SystemExit):
            self.run_cli(['0x403', 'x', '2'])
