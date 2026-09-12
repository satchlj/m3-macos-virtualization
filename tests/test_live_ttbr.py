from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_pt import validate_root_switch, PAGE
from probe_fixtures import Tables, HIGH


class LiveRootTests(unittest.TestCase):
    def setUp(self):
        self.t=Tables();self.pc=HIGH+0x10000;self.vector=HIGH+0x18000
        self.t.map(self.pc,self.t.pc);self.t.map(self.vector,self.t.base+0x44000)
        self.root=self.t.base+3*PAGE;self.t.memory.add_page(self.root)

    def check(self, **kwargs):
        args=dict(controls=self.t.controls,register='ttbr0',value=self.root,pc=self.pc,
            sp=self.t.sp,vector=self.vector,base=self.t.base,size=self.t.size,
            read_page=lambda address:self.t.memory.read(address,PAGE))
        args.update(kwargs)
        return validate_root_switch(**args)

    def test_empty_lower_root_retains_high_continuation(self):
        result=self.check()
        self.assertEqual(result['candidate_leaves'],0)
        self.assertEqual(result['continuation']['pc']['pa'],self.t.pc)
        self.assertEqual(result['controls']['ttbr0'],self.root)

    def test_candidate_leaf_outside_guest_and_cycle_rejected(self):
        old=self.t.low;self.t.low=self.root
        self.t.map(0,self.t.base+self.t.size)
        self.t.low=old
        with self.assertRaisesRegex(ValueError,'leaf leaves'):
            self.check()
        self.t.put((self.root,0),self.root|3)
        with self.assertRaisesRegex(ValueError,'Cyclic'):
            self.check()

    def test_profile_root_tags_and_table_budget_rejected(self):
        with self.assertRaisesRegex(ValueError,'profile'):
            self.check(controls=dict(self.t.controls,tcr=0))
        with self.assertRaisesRegex(ValueError,'root'):
            self.check(value=self.root|(1<<48))
        with self.assertRaisesRegex(ValueError,'budget'):
            self.check(max_pages=1)

    def test_continuation_backing_and_permissions_rejected(self):
        old=self.t.high;self.t.high=self.root
        pc_path=self.t.map(self.pc,self.t.pc+PAGE)
        self.t.map(self.vector,self.t.base+0x44000)
        self.t.map(self.t.sp-16,self.t.base+0x80000,flags=0x403|(3<<53))
        self.t.high=old
        with self.assertRaisesRegex(ValueError,'backing'):
            self.check(register='ttbr1')
        self.t.put(pc_path[-1], self.t.pc|0x403|(1<<53))
        with self.assertRaisesRegex(ValueError,'execute-never'):
            self.check(register='ttbr1')
        self.t.put(pc_path[-1], self.t.pc|0x403)
        self.assertTrue(self.check(register='ttbr1')['complete_candidate_root'])


import os
@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Requires pinned callback definitions')
class LiveCallbackTests(unittest.TestCase):
    def test_real_callback_orders_switch_and_keeps_control_changes_guarded(self):
        t=Tables();vector=HIGH+0x18000;t.map(vector,t.base+0x44000)
        root=t.base+3*PAGE;t.memory.add_page(root)
        # Copy the root; lower tables remain shared in this synthetic case.
        t.memory.write(root,t.memory.read(t.low,PAGE))
        endpoint=t.endpoint(os.environ['VEL2_CHECKOUT'],allow_monitor_mmu=True,allow_live_ttbr=True)
        t.enable(endpoint)
        endpoint.hardware.values[endpoint.sysreg.VBAR_EL12]=vector
        start=len(endpoint.hardware.calls)
        t.access(endpoint,endpoint.sysreg.TTBR0_EL1,value=root)
        self.assertEqual(endpoint.replies[-1],int(endpoint.EXC_RET.HANDLED))
        self.assertEqual(endpoint.report['trace'][-1]['kind'],'validated-live-ttbr-switch')
        calls=endpoint.hardware.calls[start:]
        barrier=calls.index(('barrier','dsb ishst'))
        self.assertEqual(calls[barrier:barrier+3],[('barrier','dsb ishst'),
            ('msr',endpoint.sysreg.TTBR0_EL12,root),
            ('barrier','isb; dsb ishst; tlbi vmalle1is; dsb ish; isb')])
        self.assertTrue(endpoint.inputs)
        self.assertEqual(endpoint.report['monitor_mmu_controls']['ttbr0'],root)
        t.access(endpoint,endpoint.sysreg.TCR_EL1,value=0)
        self.assertEqual(endpoint.replies[-1],int(endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(endpoint.report['stop_reason'],'live-translation-control-change')


PPERM = 0x2020a52a302abaf5
UPERM = 0x2010002030100000


class SprrLiveRootTests(unittest.TestCase):
    def setUp(self):
        self.t=Tables();self.pc=HIGH+0x10000;self.vector=HIGH+0x18000
        self.t.map(self.pc,self.t.pc);self.t.map(self.vector,self.t.base+0x44000)
        self.root=self.t.base+3*PAGE;self.t.memory.add_page(self.root)
        self.sprr=dict(pperm=PPERM,uperm=UPERM)

    def check(self, **kwargs):
        args=dict(controls=self.t.controls,register='ttbr0',value=self.root,pc=self.pc,
            sp=self.t.sp,vector=self.vector,base=self.t.base,size=self.t.size,
            read_page=lambda address:self.t.memory.read(address,PAGE),sprr=self.sprr)
        args.update(kwargs)
        return validate_root_switch(**args)

    def test_sprr_views_reported_for_every_continuation_mapping(self):
        result=self.check()
        for name in ('pc','stack','vector'):
            self.assertIn('sprr',result['continuation'][name])
        self.assertNotIn('sprr',self.check(sprr=None)['continuation']['pc'])
        self.assertEqual(result['continuation']['vector']['sprr']['index'],0)
        self.assertTrue(result['continuation']['vector']['sprr']['kernel_execute'])
        self.assertEqual(result['continuation']['stack']['sprr']['index'],3)
        self.assertTrue(result['continuation']['stack']['sprr']['kernel_write'])
        self.assertFalse(result['complete_machine_state_validation'])

    def test_vector_execute_uses_nibble_and_guarded_world_is_rejected(self):
        self.t.map(self.vector,self.t.base+0x44000,flags=0x403|(1<<54))  # index 2 -> kernel R
        self.check(sprr=None)
        with self.assertRaisesRegex(ValueError,'execute-never: vector'):
            self.check()
        with self.assertRaisesRegex(ValueError,'Guarded-world'):
            self.check(sprr=dict(self.sprr,world='guarded'))
        self.t.map(self.vector,self.t.base+0x44000,flags=0x403|(1<<53))  # index 1: natively PXN
        with self.assertRaisesRegex(ValueError,'execute-never'):
            self.check(sprr=None)
        executable=dict(self.sprr,pperm=(PPERM & ~(0xf<<4))|(5<<4))
        self.assertTrue(self.check(sprr=executable)['continuation']['vector']['sprr']['kernel_execute'])
