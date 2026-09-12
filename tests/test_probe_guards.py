"""Guard pauses and vector-visit stops through the real probe callback, offline."""
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from guest_pt import PAGE
from guarded_pause import GuardedPause, submit, read_json
from guest_exception_stop import GuestExceptionStop
from probe_fixtures import Tables, ENABLED_SCTLR, VHE_HCR, HIGH
from step_batch import StepBatch, RECORD


class FakePause:
    """Scripted decision channel; records what the probe asked and when."""
    def __init__(self, action='resume', changes=None, error=None, observe=None):
        self.action, self.changes, self.error, self.observe = action, changes or {}, error, observe
        self.waits = []

    def wait(self, reason, context, policies, *, allowed_flags=(), on_pause=None):
        record = dict(reason=reason, context=context, policies=dict(policies),
                      allowed_flags=list(allowed_flags), observed=None)
        self.waits.append(record)
        if on_pause:
            on_pause(Path('/unused/pause'), dict(pause_id='p'*32, state='paused'))
        if self.observe:
            record['observed'] = self.observe()
        if self.error:
            raise self.error
        return dict(action=self.action, changes=dict(self.changes), pause_id='p'*32,
                    request_id='r'*32, reason='command')


class Transport:
    """Two recorded native steps; counts how often the batch is read."""
    def __init__(self, pcs):
        self.pcs, self.counts, self.configs = pcs, 0, []

    def hv_vel2_trace_count(self):
        self.counts += 1
        return len(self.pcs)

    def readmem(self, address, length):
        return b''.join(RECORD.pack(pc, 0x32 << 26, 0, 4, *range(35)) for pc in self.pcs)[:length]

    def hv_vel2_trace_config(self, address, capacity):
        self.configs.append((address, capacity))


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class GuardPauseCallbackTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()
        self.vector = HIGH+0x18000
        self.t.map(self.vector, self.t.base+0x44000)
        self.root = self.t.base+3*PAGE
        self.t.memory.add_page(self.root)
        self.t.memory.write(self.root, self.t.memory.read(self.t.low, PAGE))

    def enabled(self, **kwargs):
        endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, **kwargs)
        self.t.enable(endpoint)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        endpoint.hardware.values[endpoint.sysreg.VBAR_EL12] = self.vector
        endpoint.hardware.calls.clear()
        return endpoint

    def root_writes(self, endpoint, calls=None):
        calls = endpoint.hardware.calls if calls is None else calls
        return [c for c in calls if c[0] == 'msr' and c[1] == endpoint.sysreg.TTBR0_EL12]

    def test_resume_retries_same_trap_with_one_drain_append_and_exit(self):
        endpoint = self.enabled()
        transport = Transport([0x2000, 0x2004])
        batch = StepBatch(transport, transport, 0x1000, 64)
        batch.armed = True
        endpoint.namespace['batch'] = batch
        pause = FakePause(changes={'allow_live_ttbr': True},
                          observe=lambda: dict(calls=list(endpoint.hardware.calls),
                                               events=endpoint.report['trace_total_events'],
                                               saved=endpoint.saved[-1]))
        endpoint.namespace['guard_pause'] = pause
        events = endpoint.report['trace_total_events']
        before, after = self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.root)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        self.assertEqual(endpoint.report['trace'][-1]['kind'], 'validated-live-ttbr-switch')
        self.assertNotIn('stop_reason', endpoint.report)
        # One batch drain, one appended trap event, one reply.
        self.assertEqual(transport.counts, 1)
        self.assertEqual(endpoint.report['native_batched_events'], 2)
        self.assertEqual(endpoint.report['trace_total_events'], events+3)
        self.assertEqual([e['pc'] for e in endpoint.report['trace'][-3:-1]], [0x2000, 0x2004])
        wait, = pause.waits
        self.assertEqual(wait['reason'], 'live-translation-control-change')
        self.assertEqual(wait['allowed_flags'], ['allow_live_ttbr'])
        self.assertEqual(wait['policies'], {'allow_monitor_mmu': True, 'allow_live_ttbr': False})
        self.assertEqual(wait['context']['kind'], 'probe-el2-register')
        self.assertEqual(wait['context']['value'], self.root)
        # While paused: batch already drained, no root write, nothing appended, report saved with the open pause.
        self.assertEqual(wait['observed']['events'], events+2)
        self.assertEqual(self.root_writes(endpoint, wait['observed']['calls']), [])
        self.assertEqual(wait['observed']['saved']['guard_pauses'][0]['decision'], None)
        self.assertEqual(self.root_writes(endpoint), [('msr', endpoint.sysreg.TTBR0_EL12, self.root)])
        self.assertEqual(after.elr, before.elr)
        self.assertTrue(endpoint.namespace['a'].allow_live_ttbr)
        record, = endpoint.report['guard_pauses']
        self.assertEqual(record['pause_id'], 'p'*32)
        self.assertEqual(record['decision']['action'], 'resume')
        self.assertEqual(record['applied_changes'], {'allow_live_ttbr': True})
        self.assertEqual(record['context']['kind'], 'probe-el2-register')
        self.assertEqual(endpoint.report['policy_overrides'], {'allow_live_ttbr': True})
        # The retry rearmed native batching only after the decision.
        self.assertEqual(transport.configs[-1][1], 64)
        # The flag is now enabled: a later root change validates without another pause.
        self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.t.low)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        self.assertEqual(len(pause.waits), 1)

    def test_exit_or_unchanged_policy_keeps_rejection_without_side_effects(self):
        for action, changes in (('exit', {}), ('resume', {}), ('resume', {'allow_monitor_mmu': True})):
            with self.subTest(action=action, changes=changes):
                self.setUp()
                endpoint = self.enabled()
                pause = FakePause(action, changes)
                endpoint.namespace['guard_pause'] = pause
                before, after = self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.root)
                self.assertEqual(endpoint.codec.build(before), endpoint.codec.build(after))
                self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.EXIT_GUEST))
                self.assertEqual(endpoint.report['stop_reason'], 'live-translation-control-change')
                self.assertEqual(self.root_writes(endpoint), [])
                self.assertEqual(len(pause.waits), 1)
                self.assertFalse(endpoint.namespace['a'].allow_live_ttbr)
                self.assertEqual(endpoint.report['guard_pauses'][0]['applied_changes'], {})
                self.assertNotIn('policy_overrides', endpoint.report)

    def test_channel_failure_exits_pending_guest_once(self):
        endpoint = self.enabled()
        endpoint.namespace['guard_pause'] = FakePause(error=OSError('pause directory unavailable'))
        replies = len(endpoint.replies)
        self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.root)
        self.assertEqual(endpoint.replies[replies:], [int(endpoint.EXC_RET.EXIT_GUEST)])
        self.assertEqual(endpoint.report['stop_reason'], 'probe-validation-error')
        self.assertIn('pause directory unavailable', endpoint.report['error'])
        self.assertEqual(self.root_writes(endpoint), [])
        self.assertFalse(endpoint.namespace['a'].allow_live_ttbr)

    def test_monitor_profile_pause_validates_tables_only_after_resume(self):
        endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'])
        self.t.configure(endpoint)
        pause = FakePause(changes={'allow_monitor_mmu': True},
                          observe=lambda: dict(reads=list(self.t.memory.reads), calls=list(endpoint.hardware.calls)))
        endpoint.namespace['guard_pause'] = pause
        endpoint.hardware.calls.clear()
        self.t.memory.reads.clear()
        before, after = self.t.access(endpoint, endpoint.sysreg.SCTLR_EL2, value=ENABLED_SCTLR)
        self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
        self.assertEqual(endpoint.report['trace'][-1]['kind'], 'monitor-mmu-enabled')
        wait, = pause.waits
        self.assertEqual(wait['reason'], 'monitor-translation-contract')
        self.assertEqual(wait['allowed_flags'], ['allow_monitor_mmu'])
        self.assertEqual(wait['context']['kind'], 'probe-control')
        self.assertEqual(wait['observed']['reads'], [])
        self.assertFalse(any(c[0] in ('msr', 'barrier') for c in wait['observed']['calls']))
        self.assertEqual(endpoint.hardware.calls[-3:], [
            ('barrier', 'dsb ishst; tlbi vmalle1is; dsb ish; isb'),
            ('msr', endpoint.sysreg.SCTLR_EL12, ENABLED_SCTLR), ('barrier', 'isb')])
        self.assertIn('monitor_mmu_address_checks', endpoint.report)
        self.assertEqual(after.elr, before.elr)
        self.assertEqual(endpoint.report['policy_overrides'], {'allow_monitor_mmu': True})

    def test_only_recognized_policy_rejections_pause(self):
        endpoint = self.enabled()
        pause = FakePause(changes={'allow_live_ttbr': True, 'allow_monitor_mmu': True})
        endpoint.namespace['guard_pause'] = pause
        s = endpoint.sysreg
        self.t.access(endpoint, s.TCR_EL1, value=0)
        self.assertEqual(endpoint.report['stop_reason'], 'live-translation-control-change')
        endpoint.report.pop('stop_reason')
        self.t.access(endpoint, s.HCR_EL2, value=0)
        self.assertEqual(endpoint.report['stop_reason'], 'monitor-translation-contract')
        self.assertEqual(pause.waits, [])
        # The recognized profile without VHE or with staged SPRR is a contract stop, not a pause.
        for sprr in (False, True):
            endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'])
            endpoint.namespace['guard_pause'] = pause
            if sprr:
                self.t.configure(endpoint)
                self.t.access(endpoint, s.SPRR_CONFIG_EL1, value=1)
            self.t.access(endpoint, s.SCTLR_EL2, value=ENABLED_SCTLR)
            self.assertEqual(endpoint.report['stop_reason'], 'monitor-translation-contract')
        self.assertEqual(pause.waits, [])
        # A disabled channel never changes behaviour.
        endpoint = self.enabled()
        self.t.access(endpoint, s.TTBR0_EL1, value=self.root)
        self.assertEqual(endpoint.report['stop_reason'], 'live-translation-control-change')
        self.assertNotIn('guard_pauses', endpoint.report)

    def test_real_channel_resume_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            endpoint = self.enabled()
            endpoint.namespace['guard_pause'] = GuardedPause(tmp, timeout_seconds=10, poll_seconds=.01)
            def decide():
                deadline = time.monotonic()+10
                while time.monotonic() < deadline:
                    for status in Path(tmp).glob('*/status.json'):
                        submit(status.parent, 'resume', {'allow_live_ttbr': True})
                        return
                    time.sleep(.01)
            thread = threading.Thread(target=decide)
            thread.start()
            self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.root)
            thread.join(10)
            self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.HANDLED))
            self.assertEqual(endpoint.report['trace'][-1]['kind'], 'validated-live-ttbr-switch')
            record, = endpoint.report['guard_pauses']
            status = read_json(Path(tmp)/record['pause_id']/'status.json')
            self.assertEqual(status['state'], 'decided')
            self.assertEqual(status['decision']['request_id'], record['decision']['request_id'])
            self.assertEqual(status['context']['kind'], 'probe-el2-register')
            self.assertEqual(status['allowed_flags'], ['allow_live_ttbr'])
        with tempfile.TemporaryDirectory() as tmp:
            self.setUp()
            endpoint = self.enabled()
            endpoint.namespace['guard_pause'] = GuardedPause(tmp, timeout_seconds=.05, poll_seconds=.01)
            self.t.access(endpoint, endpoint.sysreg.TTBR0_EL1, value=self.root)
            self.assertEqual(endpoint.replies[-1], int(endpoint.EXC_RET.EXIT_GUEST))
            self.assertEqual(endpoint.report['stop_reason'], 'live-translation-control-change')
            self.assertEqual(endpoint.report['guard_pauses'][0]['decision']['reason'], 'timeout')
            self.assertEqual(self.root_writes(endpoint), [])


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class VectorStopCallbackTests(unittest.TestCase):
    def setUp(self):
        self.t = Tables()
        self.vector = HIGH+0x18000
        self.endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'])
        self.s = self.endpoint.sysreg
        self.endpoint.namespace['vector_stop'] = GuestExceptionStop(0)
        self.endpoint.hardware.values[self.s.VBAR_EL12] = self.vector

    def step(self, pc):
        return self.endpoint.feed(dict(self.t.event(0xca000022), pc=pc))

    def vbar_reads(self):
        return [c for c in self.endpoint.hardware.calls if c == ('mrs', self.s.VBAR_EL12)]

    def test_first_recorded_vector_pc_exits_with_stop_time_registers(self):
        self.step(self.vector-4)
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED)])
        self.assertEqual(len(self.vbar_reads()), 1)
        self.assertNotIn('guest_vector_stop', self.endpoint.report)
        self.endpoint.hardware.values[self.s.ESR_EL12] = 0x96000005
        self.step(self.vector+0x200)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.EXIT_GUEST))
        self.assertEqual(self.endpoint.report['stop_reason'], 'guest-vector-range-entry')
        hit = self.endpoint.report['guest_vector_stop']
        self.assertEqual(hit['trace_index'], 1)
        self.assertEqual(hit['event']['pc'], self.vector+0x200)
        self.assertEqual(hit['sampled_vbar'], self.vector)
        self.assertEqual(hit['recorded_events_after_hit'], 0)
        self.assertIn('not-proven-first-entry', hit['cause_status'])
        self.assertEqual(hit['stop_guest_exception_registers']['ESR_EL12'], 0x96000005)
        self.assertEqual(hit['stop_guest_exception_registers']['VBAR_EL12'], self.vector)
        self.assertEqual(self.endpoint.operations[-1], 'exit-reply')

    def test_batched_vector_visit_is_found_with_bounded_overshoot(self):
        transport = Transport([self.vector+8, 0x2000])
        batch = StepBatch(transport, transport, 0x1000, 64)
        batch.armed = True
        self.endpoint.namespace['batch'] = batch
        self.endpoint.namespace['vector_stop'] = GuestExceptionStop(64)
        self.step(0x2004)
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        hit = self.endpoint.report['guest_vector_stop']
        self.assertEqual(hit['trace_index'], 0)
        self.assertEqual(hit['recorded_events_after_hit'], 2)
        self.assertEqual(hit['maximum_recorded_overshoot'], 64)
        self.assertEqual(self.endpoint.report['trace_total_events'], 3)
        # The guest was not rearmed after the stop.
        self.assertEqual(transport.configs[-1], (0, 0))

    def test_unconfigured_vbar_and_exit_paths_do_not_read_vbar(self):
        self.endpoint.hardware.values[self.s.VBAR_EL12] = 0
        self.step(0x100)
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.HANDLED)])
        self.assertNotIn('guest_vector_stop', self.endpoint.report)
        budget = self.t.endpoint(os.environ['VEL2_CHECKOUT'], steps=1)
        budget.namespace['vector_stop'] = GuestExceptionStop(0)
        budget.hardware.values[budget.sysreg.VBAR_EL12] = self.vector
        budget.feed(dict(self.t.event(0xca000022), pc=0x100))
        self.assertEqual(budget.replies, [int(budget.EXC_RET.HANDLED)])
        reads = [c for c in budget.hardware.calls if c[0] == 'mrs']
        self.assertEqual(reads, [('mrs', budget.sysreg.VBAR_EL12)])
        # Budget exhaustion exits before the detector runs: no further proxy reads.
        budget.feed(dict(self.t.event(0xca000022), pc=self.vector))
        self.assertEqual(budget.report['stop_reason'], 'instruction-budget')
        self.assertEqual([c for c in budget.hardware.calls if c[0] == 'mrs'], reads)
        self.assertNotIn('guest_vector_stop', budget.report)

    def test_vbar_read_failure_fails_closed(self):
        del self.endpoint.hardware.values[self.s.VBAR_EL12]
        self.step(0x100)
        self.assertEqual(self.endpoint.replies, [int(self.endpoint.EXC_RET.EXIT_GUEST)])
        self.assertEqual(self.endpoint.report['stop_reason'], 'vector-stop-error')
        self.assertIn('Unexpected hardware access', self.endpoint.report['error'])

    def test_cause_snapshot_failure_preserves_hit(self):
        del self.endpoint.hardware.values[self.s.FAR_EL12]
        self.step(self.vector)
        self.assertEqual(self.endpoint.report['stop_reason'], 'guest-vector-range-entry')
        self.assertEqual(self.endpoint.report['guest_vector_stop']['trace_index'], 0)
        self.assertEqual(self.endpoint.report['guest_vector_stop']['cause_status'], 'not-yet-sampled')
        self.assertIn('Unexpected hardware access', self.endpoint.report['guest_vector_stop_error'])

    def test_entry_guard_inside_vector_range_is_not_a_visit(self):
        endpoint = self.t.endpoint(os.environ['VEL2_CHECKOUT'], entered=False)
        endpoint.namespace['vector_stop'] = GuestExceptionStop(0)
        endpoint.hardware.values[endpoint.sysreg.VBAR_EL12] = self.t.pc
        self.t.memory.add_page(self.t.pc & -PAGE)
        self.t.memory.write(self.t.pc, b'\xaa\xbb\xcc\xdd')
        endpoint.feed(dict(self.t.event(0x5a007ffe), pc=self.t.pc+4, spsr=0xa0000005))
        self.assertEqual(endpoint.replies, [int(endpoint.EXC_RET.HANDLED)])
        self.assertEqual(endpoint.report['trace'][-1]['kind'], 'entry-guard')
        endpoint.feed(dict(self.t.event(0xca000022), pc=self.t.pc))
        self.assertEqual(endpoint.report['stop_reason'], 'guest-vector-range-entry')
        self.assertEqual(endpoint.report['guest_vector_stop']['trace_index'], 1)
