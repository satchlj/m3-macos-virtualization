from pathlib import Path
from types import SimpleNamespace
import sys
import os
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from boot_data_audit import audit_tree, SEGMENT


class Tree:
    def __init__(self, entries, nodes=()):
        self.mmap=SimpleNamespace(_properties=entries);self.nodes=nodes
    def __getitem__(self,key):
        assert key=='/chosen/memory-map'
        return self.mmap
    def walk_tree(self):return iter(self.nodes)


class BootDataAuditTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'),'Requires the pinned ADT parser')
    def test_real_adt_serialization_round_trip(self):
        sys.path.insert(0,str(Path(os.environ['VEL2_CHECKOUT'])/'proxyclient'))
        from m1n1.adt import ADTNode,ADTNodeStruct,ADT2Tuple
        tree=ADTNode();tree.name='device-tree';tree.create_node('chosen')
        mmap=tree.create_node('chosen/memory-map')
        mmap._types['RTBuddySeg']=(ADT2Tuple,False);mmap.RTBuddySeg=(0x8000,0x4000)
        tree.create_node('arm-io');node=tree.create_node('arm-io/test')
        node.segment_names='__OS_LOG';node.segment_ranges=SEGMENT.pack(0x8000,0,0,0x4000,0)
        encoded=tree.build();decoded=ADTNode(ADTNodeStruct.parse(encoded))
        result=audit_tree(decoded,0x10000,0x8000)
        self.assertEqual(len(result['ranges']),2)
        self.assertTrue(all(r['ownership']=='outside-owned-guest-ram' for r in result['ranges']))
        self.assertEqual(decoded.build(),encoded)

    def test_owned_foreign_virtual_and_empty_ranges(self):
        class DecodedInt(int):pass
        tree=Tree({'owned':[DecodedInt(0x10000),0x4000],'stale':[0x8000,0x4000],
                   'SPTM-entry':[0xfffffe0000000000,0],'empty':[0x8000,0]})
        rows={x['name']:x for x in audit_tree(tree,0x10000,0x8000)['ranges']}
        self.assertEqual(rows['owned']['ownership'],'owned')
        self.assertEqual(rows['stale']['ownership'],'outside-owned-guest-ram')
        self.assertEqual(rows['empty']['ownership'],'empty')
        self.assertNotIn('SPTM-entry',rows)
        self.assertEqual(tree.mmap._properties['stale'],[0x8000,0x4000])
    def test_public_segment_layout_and_malformed_metadata(self):
        node=SimpleNamespace(_path='/arm-io/example',segment_names='__TEXT;__OS_LOG',
            segment_ranges=SEGMENT.pack(0x10000,0x2000,0,0x4000,7)+SEGMENT.pack(0x8000,0x3000,0,0x4000,8))
        result=audit_tree(Tree({},[node]),0x10000,0x8000)
        self.assertEqual(result['ranges'][1]['name'],'__OS_LOG')
        self.assertEqual(result['ranges'][1]['address'],0x8000)
        self.assertEqual(result['ranges'][1]['unknown'],8)
        node.segment_names='wrong-count'
        self.assertTrue(audit_tree(Tree({},[node]),0x10000,0x8000)['parse_issues'])
    def test_overflow_is_not_an_owned_range(self):
        result=audit_tree(Tree({'overflow':[(1<<64)-4,8]}),0x10000,0x8000)
        self.assertEqual(result['ranges'][0]['ownership'],'invalid-range')
