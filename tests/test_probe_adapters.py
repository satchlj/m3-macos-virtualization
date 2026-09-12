"""Adapters regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import FastShadowProxy, StepFilterProxy
import unittest
from types import SimpleNamespace
from sptm_entry_probe import (
    TpidrGl2FastShadow,
    audit_and_disable_tpidr_gl2_fast_shadow,
    Vel2StepFilter,
)


class TpidrGl2FastShadowTests(unittest.TestCase):
    def test_strict_adapter_preflight_enable_audit_and_disable(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        preflight = adapter.prepare()
        self.assertFalse(preflight['after']['enabled'])
        enabled = adapter.enable(0x9140, 0xfffffe0007106200)
        self.assertEqual((enabled['tag_base'], enabled['shadow']),
                         (0x9140, 0xfffffe0007106200))
        proxy.state.update(shadow=0x1234, reads=248, writes=1)
        host_shadow = {'tpidr': 0}
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, host_shadow, 'tpidr')
        self.assertEqual(errors, [])
        self.assertEqual(host_shadow['tpidr'], 0x1234)
        self.assertEqual(result['stop_audit']['reads'], 248)
        self.assertEqual(result['stop_audit']['writes'], 1)
        self.assertTrue(result['disabled_at_teardown'])
        self.assertFalse(result['disable_status']['enabled'])


class Vel2StepFilterTests(unittest.TestCase):
    def test_preflight_enable_terminal_audit_and_disable(self):
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        self.assertFalse(adapter.prepare()['after']['active'])
        enabled = adapter.enable((0x1000, 0x1100), (0x2000, 0x2100),
                                 0x3000, 4096, 0x1004)
        self.assertTrue(enabled['active'])
        proxy.state.update(active=False, status=Vel2StepFilter.TERMINAL,
                           steps=123, first_pc=0x1004, last_pc=0x3000,
                           previous_pc=0x2004, range0_hits=100,
                           range1_hits=23, range_switches=2)
        teardown = adapter.disable()
        self.assertEqual(teardown['before']['status'],
                         Vel2StepFilter.TERMINAL)
        self.assertEqual(teardown['before']['steps'], 123)
        self.assertEqual(teardown['after']['status'], 0)

    def test_missing_schema_or_readback_mismatch_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'proxy API unavailable'):
            Vel2StepFilter(SimpleNamespace())
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        proxy.hv_vel2_step_filter_status = lambda: {'active': False}
        with self.assertRaisesRegex(RuntimeError, 'status missing'):
            adapter.prepare()
        proxy = StepFilterProxy()
        adapter = Vel2StepFilter(proxy)
        original = proxy.hv_vel2_step_filter_status
        def wrong_range():
            status = original()
            status['range1_end'] ^= 4
            return status
        proxy.hv_vel2_step_filter_status = wrong_range
        with self.assertRaisesRegex(RuntimeError, 'readback mismatch'):
            adapter.enable((0x1000, 0x1100), (0x2000, 0x2100),
                           0x3000, 4096, 0x1004)
        self.assertIn(('disable',), proxy.calls)
        self.assertFalse(proxy.state['active'])


class TpidrGl2FastShadowFailureTests(unittest.TestCase):
    def test_missing_or_malformed_proxy_api_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'proxy API unavailable'):
            TpidrGl2FastShadow(SimpleNamespace())
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        proxy.hv_vel2_tpidr_gl2_shadow_status = lambda: {'enabled': False}
        with self.assertRaisesRegex(RuntimeError, 'status missing'):
            adapter.prepare()

    def test_enable_readback_mismatch_forces_disable(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        original_status = proxy.hv_vel2_tpidr_gl2_shadow_status
        calls = 0
        def mismatched_status():
            nonlocal calls
            calls += 1
            result = original_status()
            if calls == 1:
                result['shadow'] ^= 1
            return result
        proxy.hv_vel2_tpidr_gl2_shadow_status = mismatched_status
        with self.assertRaisesRegex(RuntimeError, 'readback mismatch'):
            adapter.enable(0x9140, 0x1234)
        self.assertIn(('disable',), proxy.calls)
        self.assertFalse(proxy.state['enabled'])

    def test_teardown_attempts_disable_when_stop_audit_fails(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        adapter.enable(0x9140, 0x1234)
        calls = 0
        original_status = proxy.hv_vel2_tpidr_gl2_shadow_status
        def one_failed_status():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError('audit unavailable')
            return original_status()
        proxy.hv_vel2_tpidr_gl2_shadow_status = one_failed_status
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, {}, 'tpidr')
        self.assertIn('stop audit failed', errors[0])
        self.assertTrue(result['disabled_at_teardown'])
        self.assertFalse(proxy.state['enabled'])

    def test_teardown_before_activation_does_not_replace_host_shadow(self):
        proxy = FastShadowProxy()
        adapter = TpidrGl2FastShadow(proxy)
        host_shadow = {'tpidr': 0xfeed}
        result, errors = audit_and_disable_tpidr_gl2_fast_shadow(
            adapter, host_shadow, 'tpidr', synchronize=False)
        self.assertEqual(errors, [])
        self.assertEqual(host_shadow['tpidr'], 0xfeed)
        self.assertFalse(result['host_shadow_synchronized'])
        self.assertTrue(result['disabled_at_teardown'])
