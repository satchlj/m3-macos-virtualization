"""Synthetic load-command fixtures; no Apple images or target access."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from sptm_layout import image, plan, PAGE

NAMES = {
    'sptm': ['__TEXT','__DATA_CONST','__LATE_CONST','__TEXT_EXEC','__LAST','__DATA','__BOOTDATA','__LINKEDIT'],
    'txm': ['__TEXT','__DATA_CONST','__TEXT_EXEC','__TEXT_BOOT_EXEC','__DATA','__LINKEDIT'],
    'kernelcache': ['__TEXT','__PRELINK_TEXT','__DATA_CONST','__DATA_SPTM','__TEXT_EXEC','__TEXT_BOOT_EXEC','__PRELINK_INFO','__DATA','__LINKEDIT'],
}
BASES = dict(sptm=0xfffffff027004000,txm=0xfffffff017004000,kernelcache=0xfffffe0007004000)


def fixture(which):
    cmds = []
    base = BASES[which]
    for i,name in enumerate(NAMES[which]):
        cmds.append(struct.pack('<II16s4Q4I',0x19,72,name.encode(),base+i*PAGE,PAGE,0,0,5,5,0,0))
    state = bytearray(272)
    struct.pack_into('<Q',state,256,base+NAMES[which].index('__TEXT_EXEC')*PAGE)
    cmds.append(struct.pack('<4I',5,288,6,68)+state)
    commands=b''.join(cmds)
    return struct.pack('<8I',0xfeedfacf,0x100000c,2,2,len(cmds),len(commands),0,0)+commands


class LayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        for which in NAMES:
            (self.root/(which+'.macho')).write_bytes(fixture(which))

    def test_segments_placed_once_without_overlap(self):
        p=plan(self.root,0x70000,0x5000)
        placed=p['placements']
        self.assertEqual(len(placed),sum(map(len,NAMES.values())))
        spans=sorted((s['offset'],s['offset']+s['size']) for s in placed)
        for a,b in zip(spans,spans[1:]):self.assertLessEqual(a[1],b[0])
        self.assertLess(p['entry_offset'],p['size'])
        self.assertFalse(p['guest_boot_verified'])
        self.assertEqual(p['regions']['SPTM-ro'][0],BASES['kernelcache'] & ((1<<36)-1))

    def test_device_tree_prefix_and_trustcache_rounding(self):
        p=plan(self.root,0x70001,0x4001)
        self.assertEqual(p['adt_offset']-p['regions']['DeviceTree'][0],PAGE)
        self.assertEqual(p['regions']['DeviceTree'][1],0x78000)
        self.assertEqual(p['regions']['TrustCache'][1],0x8000)

    def test_absent_auxiliary_regions_keep_contiguous_order(self):
        p=plan(self.root,0x70000,0x5000)
        r=p['regions']
        end=lambda name:sum(r[name])
        self.assertEqual(r['AuxKC-ro'],[end('TrustCache'),0])
        self.assertEqual(r['AuxKC-rx'],[end('AuxKC-ro'),0])
        self.assertEqual(r['BootKC-rx'][0],end('AuxKC-rx'))
        self.assertEqual(r['CL4-rx'],[end('BootKC-rs'),0])
        self.assertEqual(r['CL4-ro'],[end('CL4-rx'),0])
        self.assertEqual(r['DeviceTree'][0],end('CL4-ro'))

    def test_incompatible_virtual_stride_rejected(self):
        original=image
        def changed(path):
            v=original(path)
            if path.stem=='txm':v['vmin']+=PAGE
            return v
        with patch('sptm_layout.image',changed), self.assertRaisesRegex(ValueError,'stride'):
            plan(self.root,0x70000,0x4000)

    def test_oversized_metadata_cannot_overlap_alignment_target(self):
        with self.assertRaisesRegex(ValueError,'alignment'):
            plan(self.root,0x8000000,0x4000)
