"""Adapters regression tests, preserved from test_probe_controls."""
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from probe_control_support import FastShadowProxy, StepFilterProxy
import unittest
from types import SimpleNamespace
from sptm_entry_probe import (
    TpidrGl2FastShadow,
    audit_and_disable_tpidr_gl2_fast_shadow,
    Vel2StepFilter,
    Gl1FastRedirect,
    GL1_FAST_SITE_CONTRACT,
    phase53_hvc_gl1_counter_checks,
    verify_gl1_fast_rewrite,
)


class Gl1FastRedirectProxy:
    FIELDS = (
        'enabled', 'pc_base', 'spsr_tag', 'aspsr_tag', 'esr_tag', 'elr_tag',
        'handled', 'forwarded', 'write_spsr', 'write_elr', 'read_aspsr',
        'write_aspsr', 'read_esr', 'read_spsr', 'read_elr',
        'nested_write_elr', 'nested_write_spsr', 'nested_read_esr_0',
        'nested_read_esr_1')

    def __init__(self):
        self.state = {name: False if name == 'enabled' else 0
                      for name in self.FIELDS}
        self.calls = []

    def hv_vel2_gl1_fast_enable(self, pc_base, tags):
        self.calls.append(('enable', pc_base, dict(tags)))
        self.state.update(
            enabled=True, pc_base=pc_base, spsr_tag=tags['SPSR_GL1'],
            aspsr_tag=tags['ASPSR_GL1'], esr_tag=tags['ESR_GL1'],
            elr_tag=tags['ELR_GL1'])

    def hv_vel2_gl1_fast_status(self):
        self.calls.append(('status',))
        return dict(self.state)

    def hv_vel2_gl1_fast_disable(self):
        self.calls.append(('disable',))
        self.state.update({name: False if name == 'enabled' else 0
                           for name in self.FIELDS})

class Gl1FastRedirectTests(unittest.TestCase):
    BASE = 0xfffffe0007004000
    TAGS = dict(SPSR_GL1=0xaf80, ASPSR_GL1=0xafc0,
                ESR_GL1=0xb000, ELR_GL1=0xb040)

    def test_strict_lifecycle_and_counter_audit(self):
        proxy = Gl1FastRedirectProxy()
        adapter = Gl1FastRedirect(proxy)
        self.assertFalse(adapter.prepare()['after']['enabled'])
        enabled = adapter.enable(self.BASE, self.TAGS)
        self.assertTrue(enabled['enabled'])
        proxy.state.update(handled=8232, write_spsr=1176,
                           write_elr=1176, read_aspsr=1176,
                           write_aspsr=1176, read_esr=1176,
                           read_spsr=1176, read_elr=1176)
        teardown = adapter.disable()
        self.assertEqual(teardown['before']['handled'], 8232)
        self.assertFalse(teardown['after']['enabled'])

    def test_bad_schema_tags_and_enable_readback_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'proxy API unavailable'):
            Gl1FastRedirect(SimpleNamespace())
        proxy = Gl1FastRedirectProxy()
        adapter = Gl1FastRedirect(proxy)
        proxy.hv_vel2_gl1_fast_status = lambda: {'enabled': False}
        with self.assertRaisesRegex(RuntimeError, 'status missing'):
            adapter.prepare()
        proxy = Gl1FastRedirectProxy()
        adapter = Gl1FastRedirect(proxy)
        with self.assertRaisesRegex(RuntimeError, 'not distinct'):
            adapter.enable(self.BASE, dict(self.TAGS, ELR_GL1=0xaf80))
        original = proxy.hv_vel2_gl1_fast_status
        calls = 0
        def bad_status():
            nonlocal calls
            calls += 1
            result = original()
            if calls == 1:
                result['pc_base'] ^= 0x4000
            return result
        proxy.hv_vel2_gl1_fast_status = bad_status
        with self.assertRaisesRegex(RuntimeError, 'readback mismatch'):
            adapter.enable(self.BASE, self.TAGS)
        self.assertIn(('disable',), proxy.calls)

    def test_exact_pinned_source_and_hvc_rewrite_contract(self):
        size = max(site[1] for site in GL1_FAST_SITE_CONTRACT)
        original = bytearray(size)
        rewritten = bytearray(size)
        for _, post, word, register, imm_low in GL1_FAST_SITE_CONTRACT:
            struct.pack_into('<I', original, post - 4, word)
            imm = self.TAGS[register] | imm_low
            struct.pack_into('<I', rewritten, post - 4,
                             0xd4000002 | (imm << 5))
        sites = verify_gl1_fast_rewrite(
            original, rewritten, 0, self.TAGS)
        self.assertEqual(len(sites), 11)
        self.assertEqual(sites[0]['rewritten_word'], '0xd415f142')
        rewritten[GL1_FAST_SITE_CONTRACT[-1][1] - 4] ^= 1
        with self.assertRaisesRegex(ValueError, 'rewrite drift'):
            verify_gl1_fast_rewrite(original, rewritten, 0, self.TAGS)

    def test_phase53_hvc_counter_contract_accepts_complete_nested_sequence(self):
        before = Gl1FastRedirectProxy().state
        after = dict(before, handled=11)
        for name in Gl1FastRedirect.STATUS_FIELDS[8:15]:
            after[name] = 1
        for name in Gl1FastRedirect.STATUS_FIELDS[15:]:
            after[name] = 1
        deltas, aggregate, checks = phase53_hvc_gl1_counter_checks(
            before, after)
        self.assertTrue(all(checks.values()), (deltas, aggregate, checks))

    def test_phase53_hvc_counter_contract_accepts_no_nested_sequence(self):
        before = Gl1FastRedirectProxy().state
        after = dict(before, handled=7)
        for name in Gl1FastRedirect.STATUS_FIELDS[8:15]:
            after[name] = 1
        deltas, aggregate, checks = phase53_hvc_gl1_counter_checks(
            before, after)
        self.assertTrue(all(checks.values()), (deltas, aggregate, checks))

    def test_phase53_hvc_counter_contract_rejects_partial_nested_sequence(self):
        before = Gl1FastRedirectProxy().state
        after = dict(before, handled=8)
        for name in Gl1FastRedirect.STATUS_FIELDS[8:15]:
            after[name] = 1
        after['nested_write_elr'] = 1
        _, _, checks = phase53_hvc_gl1_counter_checks(before, after)
        self.assertFalse(checks['gl1_nested_sequence'])

    def test_phase53_hvc_counter_contract_rejects_forwarded_access(self):
        before = Gl1FastRedirectProxy().state
        after = dict(before, handled=7, forwarded=1)
        for name in Gl1FastRedirect.STATUS_FIELDS[8:15]:
            after[name] = 1
        _, _, checks = phase53_hvc_gl1_counter_checks(before, after)
        self.assertFalse(checks['gl1_forwarded_delta'])


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
