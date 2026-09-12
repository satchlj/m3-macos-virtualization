import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from zero_loop import PATTERN, recognize

class ZeroLoopTests(unittest.TestCase):
    def test_bounded_fill_effects(self):
        r=recognize(PATTERN,[0,0x1800,256],0x1100,0x1000,0x1000)
        self.assertEqual(r,dict(address=0x1800,bytes=2048,x1=0x2000,x2=0,pc=0x110c,nzcv=6,emulated_instructions=768))

    def test_refuses_out_of_allocation_and_wraparound(self):
        for pointer,count in [(0xff8,1),(0x2000,1),(0x1ff8,2),((1<<64)-8,2)]:
            self.assertIsNone(recognize(PATTERN,[0,pointer,count],0x1100,0x1000,0x1000))

    def test_refuses_different_program_or_values(self):
        self.assertIsNone(recognize(b'\0'*12,[0,0x1000,1],0x1100,0x1000,0x1000))
        for regs in ([1,0x1000,1],[0,0x1001,1],[0,0x1000,0],[0,0x1000,8193]):
            self.assertIsNone(recognize(PATTERN,regs,0x1100,0x1000,0x20000))
