from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_handoff import classify_entry
from probe_fixtures import Tables, HIGH


class HandoffClassificationTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()
        self.target = HIGH + 0x17070000
        self.pa = self.t.base + 0x40000
        self.t.memory.add_page(self.pa)
        self.t.memory.write(self.pa, b'A' * 64)
        self.t.map(self.target, self.pa)
        self.layout = dict(virtual_base=HIGH, size=self.t.size, regions={},
                           placements=[dict(image='txm',segment='__TEXT_BOOT_EXEC',offset=0x40000,size=0x4000)],
                           images={'txm':dict(entry=0x6000, segments={'__TEXT_BOOT_EXEC':
                               dict(va=0x6000,fileoff=0,filesize=64,size=0x4000)})})

    def classify(self, **kwargs):
        return classify_entry(self.target, self.layout, self.t.base, self.t.size,
                              dict(ttbr0=self.t.low,ttbr1=self.t.high),
                              kwargs.get('readmem', self.t.memory.read), {'txm':b'A'*64})

    def test_remapped_txm_entry_identified_by_physical_placement_and_bytes(self):
        r = self.classify()
        self.assertEqual(r['image'], 'txm')
        self.assertTrue(r['entry_matches'] and r['bytes_match'])
        self.assertFalse(r['instructions_executed'])

    def test_changed_bytes_and_interior_pc_do_not_verify_entry(self):
        self.t.memory.write(self.pa,b'B')
        self.assertFalse(self.classify()['bytes_match'])
        self.target += 4
        self.assertFalse(self.classify()['entry_matches'])

    def test_mapping_outside_owned_guest_ram_rejected_before_read(self):
        self.t.map(self.target, self.t.base+self.t.size)
        with self.assertRaisesRegex(ValueError,'outside owned'):
            self.classify()
