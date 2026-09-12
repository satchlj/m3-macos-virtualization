import ctypes as C
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from step_batch import StepBatch,RECORD


class Record(C.Structure):
    _fields_=[('pc',C.c_uint64),('esr',C.c_uint64),('far',C.c_uint64),('pstate',C.c_uint64),('regs',C.c_uint64*32),('sp',C.c_uint64*3)]
class State(C.Structure):
    _fields_=[('records',C.POINTER(Record)),('capacity',C.c_uint64),('count',C.c_uint64)]


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'),'Requires native source checkout')
class NativeBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup)
        path=Path(cls.temp.name)/'trace.so'
        subprocess.run([shutil.which('cc'),'-shared','-fPIC','-Wall','-Werror',str(Path(os.environ['VEL2_CHECKOUT'])/'src/vel2_trace.c'),'-o',str(path)],check=True)
        cls.lib=C.CDLL(str(path))
        cls.lib.vel2_trace_configure.argtypes=[C.POINTER(State),C.POINTER(Record),C.c_uint64]
        cls.lib.vel2_trace_push.argtypes=[C.POINTER(State),C.POINTER(Record)]
        cls.lib.vel2_trace_push.restype=C.c_bool

    def test_capacity_order_and_nonstep_rejection(self):
        state=State();buffer=(Record*2)()
        self.assertEqual(C.sizeof(Record),RECORD.size)
        self.assertEqual(self.lib.vel2_trace_configure(C.byref(state),buffer,2),0)
        for pc in (4,8):
            record=Record(pc=pc,esr=0x32<<26,pstate=4)
            self.assertTrue(self.lib.vel2_trace_push(C.byref(state),C.byref(record)))
        record.pc=12
        self.assertFalse(self.lib.vel2_trace_push(C.byref(state),C.byref(record)))
        self.assertEqual([r.pc for r in buffer],[4,8])
        self.assertEqual(self.lib.vel2_trace_configure(C.byref(state),buffer,257),-1)
        self.assertEqual(state.count,2)
        self.lib.vel2_trace_configure(C.byref(state),buffer,2)
        for esr,mode in [(0x16<<26,4),(0x18<<26,4),(0x32<<26,0),(0x32<<26,9)]:
            record.esr,record.pstate=esr,mode
            self.assertFalse(self.lib.vel2_trace_push(C.byref(state),C.byref(record)))
        self.assertEqual(state.count,0)
        self.lib.vel2_trace_configure(C.byref(state),None,0)
        record.esr,record.pstate=0x32<<26,4
        self.assertFalse(self.lib.vel2_trace_push(C.byref(state),C.byref(record)))


class HostBatchTests(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.count=2
        self.data=b''.join(RECORD.pack(pc,0x32<<26,0,4,*range(35))for pc in (4,8))
        self.batch=StepBatch(self,self,0x1000,64);self.batch.armed=True
    def hv_vel2_trace_count(self):return self.count
    def readmem(self,address,length):return self.data[:length]
    def hv_vel2_trace_config(self,address,capacity):self.calls.append((address,capacity))
    def test_drain_preserves_order_and_budget_limits_next_batch(self):
        report={'trace':[]};self.batch.drain(report)
        self.assertEqual([e['pc']for e in report['trace']],[4,8])
        self.assertEqual(report['native_batched_events'],2)
        self.batch.arm(report,5)
        self.assertEqual(self.calls,[(0,0),(0x1000,3)])
    def test_bad_count_or_short_read_does_not_acknowledge(self):
        for count,data in [(65,self.data),(2,b'bad')]:
            self.count,self.data=count,data
            with self.assertRaises(ValueError):self.batch.drain({'trace':[]})
            self.assertEqual(self.calls,[])

    def test_drain_enforces_smaller_armed_quota(self):
        self.batch.arm({'trace': []}, 1)
        self.calls.clear()
        with self.assertRaises(ValueError):
            self.batch.drain({'trace': []})
        self.assertEqual(self.calls, [])

    def test_synthetic_gate_rejects_missing_or_duplicated_steps(self):
        from step_batch_smoke import validate
        import copy
        first = 0x1000
        steps = [dict(kind='instruction-step', pc=first+4*n, regs=[n]) for n in range(1,65)]
        report = dict(capacity=8, native_batched_events=57, proxy_alive_after_exit=True,
                      trace=steps+[dict(kind='terminal-hvc', esr=0x5a007fff, regs=[64])])
        self.assertTrue(all(validate(report, first, first+256).values()))
        altered = copy.deepcopy(report)
        altered['trace'][31] = altered['trace'][30]
        self.assertFalse(all(validate(altered, first, first+256).values()))
        altered = copy.deepcopy(report)
        del altered['trace'][31]
        self.assertFalse(validate(altered, first, first+256)['step_count'])

@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'),'Requires callback source checkout')
class BatchCallbackTests(unittest.TestCase):
    def test_pending_steps_are_counted_before_host_budget_check(self):
        from replay_debug_probe import CallbackReplay
        endpoint=CallbackReplay(Path(os.environ['VEL2_CHECKOUT']),steps=2)
        class Transport:
            def hv_vel2_trace_count(self):return 2
            def readmem(self,a,n):return b''.join(RECORD.pack(pc,0x32<<26,0,4,*range(35))for pc in (4,8))
            def hv_vel2_trace_config(self,a,n):pass
        transport=Transport();batch=StepBatch(transport,transport,0x1000,64);batch.armed=True
        endpoint.namespace['batch']=batch
        endpoint.feed(dict(reason=2,code=0,pc=12,esr=0x32<<26,spsr=4,regs=[0]*32,sp=[0]*3,far=0))
        self.assertEqual(endpoint.report['trace_total_events'],3)
        self.assertEqual([e.get('pc')for e in endpoint.report['trace']],[4,8,None])
        self.assertEqual(endpoint.report['stop_reason'],'instruction-budget')
        self.assertEqual(endpoint.replies,[int(endpoint.EXC_RET.EXIT_GUEST)])
