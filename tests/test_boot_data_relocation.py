from pathlib import Path
from types import SimpleNamespace
import os
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from boot_data_relocation import plan_copies, relocate_tree, read_copy
from boot_data_audit import SEGMENT


class RelocationTests(unittest.TestCase):
    def test_bounded_reads_and_truncation(self):
        calls = []
        def reader(address, size):
            calls.append((address, size))
            return b'x'*size
        self.assertEqual(read_copy(reader, 0x1000, 0x10001), b'x'*0x10001)
        self.assertEqual(calls, [(0x1000, 0x10000), (0x11000, 1)])
        with self.assertRaises(ValueError):
            read_copy(lambda a, n: b'', 0x1000, 4)

    def test_overlap_is_copied_once_and_offsets_preserved(self):
        mmap = SimpleNamespace(_properties={'RTBuddySeg': (0x18000, 0x8000),
            'SEPFW': (0x1c000, 0x10000), 'preoslog': (0x30000, 0x4000)})
        plan = plan_copies(mmap, 0x10000, 0x40000, 0x9000)
        self.assertEqual([(s['start'], s['size'], s['offset']) for s in plan['spans']],
                         [(0x18000, 0x14000, 0xc000), (0x30000, 0x4000, 0x20000)])
        self.assertEqual(plan['end_offset'], 0x24000)

    def test_rejects_external_overlarge_and_noninteger_inputs(self):
        for value in [(0, 0x4000), (0x10000, -1), (0x10000, 0x2004000), (True, 0x4000)]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                plan_copies(SimpleNamespace(_properties={'RTBuddySeg': value}), 0x10000, 0x4000000, 0)

    @unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Requires pinned ADT parser')
    def test_real_tree_aliases_round_trip_and_atomic_rejection(self):
        sys.path.insert(0, str(Path(os.environ['VEL2_CHECKOUT'])/'proxyclient'))
        from m1n1.adt import ADTNode, ADTNodeStruct, ADT2Tuple
        tree = ADTNode(); tree.name = 'device-tree'; tree.create_node('chosen')
        mmap = tree.create_node('chosen/memory-map')
        mmap._types['RTBuddySeg'] = (ADT2Tuple, False)
        mmap.RTBuddySeg = (0x18000, 0x8000)
        tree.create_node('arm-io'); node = tree.create_node('arm-io/test')
        node.segment_names = '__OS_LOG;__TEXT'
        node.segment_ranges = SEGMENT.pack(0x19000, 0x900, 0x19000, 0x1000, 10) + SEGMENT.pack(0x90000, 0x800, 0, 0x4000, 7)
        original = tree.build()
        plan = plan_copies(mmap, 0x10000, 0x10000, 0x4000)
        changes = relocate_tree(tree, plan, 0x100000)
        result = ADTNode(ADTNodeStruct.parse(tree.build()))
        self.assertEqual(tuple(result['/chosen/memory-map'].RTBuddySeg), (0x104000, 0x8000))
        self.assertEqual(list(SEGMENT.iter_unpack(result['/arm-io/test'].segment_ranges)),
            [(0x105000, 0x900, 0x105000, 0x1000, 10), (0x90000, 0x800, 0, 0x4000, 7)])
        self.assertEqual(len(changes), 2)
        for fields in [(0x19000, 0x900, 0x90000, 0x1000, 10), (0x1f000, 0x900, 0, 0x2000, 10)]:
            tree = ADTNode(ADTNodeStruct.parse(original))
            tree['/arm-io/test'].segment_ranges = SEGMENT.pack(*fields) + SEGMENT.pack(0x90000, 0x800, 0, 0x4000, 7)
            before = tree.build()
            with self.assertRaises(ValueError):
                relocate_tree(tree, plan, 0x100000)
            self.assertEqual(tree.build(), before)
