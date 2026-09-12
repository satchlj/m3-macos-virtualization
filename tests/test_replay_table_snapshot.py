from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from replay_table_snapshot import walk_snapshot
from guest_pt import MONITOR_TCR,MONITOR_MAIR,PAGE


class TableReplayTests(unittest.TestCase):
    def test_unmapped_and_missing_are_distinct(self):
        controls=dict(tcr=MONITOR_TCR,mair=MONITOR_MAIR,ttbr0=0x10000,ttbr1=0x10000)
        page=bytearray(PAGE)
        result=walk_snapshot(controls,{0x10000:page},0)
        self.assertEqual(result['status'],'unmapped')
        self.assertEqual(result['path'][0]['descriptor'],0)
        struct.pack_into('<Q',page,0,0x14003)
        result=walk_snapshot(controls,{0x10000:page},0)
        self.assertEqual(result['status'],'missing-table')
        self.assertEqual(result['missing_table'],0x14000)
        leaf=bytearray(PAGE);struct.pack_into('<Q',leaf,0,0x701)
        result=walk_snapshot(controls,{0x10000:page,0x14000:leaf},0x1234)
        self.assertEqual(result['status'],'mapped')
        self.assertEqual(result['mapping']['pa'],0x1234)
    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            walk_snapshot(dict(tcr=0,mair=0),{},0)
