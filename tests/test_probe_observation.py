"""Observation regression tests, preserved from test_probe_controls."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import os
import struct
import unittest
from probe_fixtures import Tables


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class SprrObservationTests(unittest.TestCase):
    """Observation-only staging after translation is live; nothing is enforced."""
    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True)
        self.s = self.endpoint.sysreg
        self.tables.enable(self.endpoint)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.endpoint.hardware.calls.clear()

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def assert_staged(self, kind):
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], kind)
        self.assertEqual(self.endpoint.hardware.calls, [])
        self.assertEqual(self.endpoint.hardware.attempts, [])

    def test_translated_config_write_is_recorded_not_enforced(self):
        self.access(self.s.SPRR_PPERM_EL1, value=0x2020a52a302abaf5)
        self.assert_staged('staged-sprr-permission')
        before, after = self.access(self.s.SPRR_CONFIG_EL1, value=1)
        self.assert_staged('observed-sprr-config')
        self.assertEqual(after.elr, before.elr)
        observation = self.endpoint.report['sprr_observation']
        self.assertFalse(observation['enforced'])
        self.assertEqual(observation['events'][-1]['value'], 1)
        self.assertEqual(observation['events'][-1]['permissions']['SPRR_PPERM_EL1'], 0x2020a52a302abaf5)
        _, after = self.access(self.s.SPRR_CONFIG_EL1, read=True, rt=3)
        self.assertEqual(after.regs[3], 1)
        self.assert_staged('staged-sprr-config')
        # SPTM then locks the configuration; observation records the bits instead of stopping.
        self.access(self.s.SPRR_CONFIG_EL1, value=0xfb)
        self.assert_staged('observed-sprr-config')
        last = observation['events'][-1]
        self.assertEqual((last['enable'], last['lock_config'], last['lock_perm'], last['lock_kernel_perm'], last['unknown_bits']),
                         (True, True, True, True, 0xc8))
        _, after = self.access(self.s.SPRR_CONFIG_EL1, read=True, rt=4)
        self.assertEqual(after.regs[4], 0xfb)

    def test_full_sprr_permission_family_stages_without_hardware(self):
        # SPTM programmed SPRR_PMPRR_EL1 (S3_6_C15_C3_1) and shareable perm mirrors;
        # every one must stage rather than fault natively into the monitor's vector.
        for name in ('SPRR_PMPRR_EL1', 'SPRR_UPERM_SH1_EL1', 'SPRR_UPERM_SH2_EL1', 'SPRR_UPERM_SH3_EL1',
                     'SPRR_PPERM_SH1_EL1', 'SPRR_PPERM_SH2_EL1', 'SPRR_PPERM_SH3_EL1'):
            with self.subTest(register=name):
                reg = getattr(self.s, name)
                self.access(reg, value=0x2020a52a302abaf5, rt=9)
                self.assert_staged('staged-sprr-permission')
                _, after = self.access(reg, read=True, rt=10)
                self.assertEqual(after.regs[10], 0x2020a52a302abaf5)
                self.assert_staged('staged-sprr-permission')

    def test_every_apple_register_in_the_monitor_image_is_intercepted_or_allowlisted(self):
        import struct
        payload = Path(__file__).resolve().parents[1]/'local/payload/sptm.macho'
        if not payload.is_file():
            self.skipTest('Retained SPTM payload not present')
        data = payload.read_bytes()
        native = {(3, 6, 15, 2, 5), (3, 6, 15, 12, 4)}  # AFPCR_EL0, APSTS_EL1: executed natively before, without incident
        covered = set(self.endpoint.namespace['extra_regs'])
        gaps = set()
        for off in range(0, len(data)-3, 4):
            w = struct.unpack_from('<I', data, off)[0]
            if w & 0xffd00000 == 0xd5100000:
                enc = (2+((w >> 19) & 1), (w >> 16) & 7, (w >> 12) & 15, (w >> 8) & 15, (w >> 5) & 7)
                if enc[:3] in ((3, 6, 15), (3, 4, 15)) and enc not in covered and enc not in native:
                    gaps.add(enc)
        self.assertEqual(gaps, set())
        self.assertLess(len(covered), 256)

    def test_virtual_el2_aliases_and_guarded_level_stage_without_hardware(self):
        for name in ('TPIDR_GL2', 'SPRR_CONFIG_EL12', 'GXF_CONFIG_EL12', 'VBAR_GL12', 'SP_GL12', 'APIAKeyLo_EL12'):
            with self.subTest(register=name):
                reg = getattr(self.s, name)
                self.access(reg, value=0xabc, rt=3)
                self.assert_staged('staged-apple-register')
                _, after = self.access(reg, read=True, rt=4)
                self.assertEqual(after.regs[4], 0xabc)
        self.access((3, 6, 15, 0, 5), value=7, rt=1)
        self.assert_staged('staged-apple-register')
        self.assertEqual(self.endpoint.report['trace'][-1]['register'], 'S3_6_C15_C0_5')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['S3_6_C15_C0_5'], 7)

    def test_guarded_world_registers_stage_without_hardware(self):
        for register in (self.s.SPRR_AMRANGE_EL1, self.s.SPRR_UMPRR_EL1, self.s.GXF_ENTRY_EL1, self.s.GXF_PABENTRY_EL1,
                         self.s.VBAR_GL1, self.s.TPIDR_GL1, self.s.ASPSR_GL1, self.s.SPSR_GL1, self.s.ELR_GL1,
                         self.s.ESR_GL1, self.s.FAR_GL1, self.s.AFSR1_GL1, self.s.ASPSR_EL1):
            with self.subTest(register=register):
                self.access(register, value=0x1234, rt=5)
                self.assert_staged('staged-apple-register')
                _, after = self.access(register, read=True, rt=6)
                self.assertEqual(after.regs[6], 0x1234)
                self.assert_staged('staged-apple-register')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['VBAR_GL1'], 0x1234)
        _, after = self.access(self.s.GXF_STATUS_EL1, read=True, rt=7)
        self.assertEqual(after.regs[7], 0)
        self.assert_staged('staged-apple-register')
        self.access(self.s.GXF_STATUS_EL1, value=1)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')

    def test_gxf_activation_still_stops_and_default_stays_strict(self):
        self.access(self.s.SPRR_CONFIG_EL1, value=1)
        self.assert_staged('observed-sprr-config')
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.SPRR_CONFIG_EL1, value=1)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
        untranslated = self.tables.endpoint(os.environ['VEL2_CHECKOUT'])
        self.tables.access(untranslated, self.s.SPRR_CONFIG_EL1, value=0xfb)
        self.assertEqual(untranslated.report['stop_reason'], 'unsupported-el2-register')
        self.assertNotIn('sprr_observation', strict.report)


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class VirtualGuardedWorldTests(unittest.TestCase):
    """Architectural genter/gexit control flow only; nothing is enforced."""
    ENTRY = 0xfffffe0007100000
    GL_VECTOR = 0xfffffe0007200000

    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True, virtual_gxf=True)
        self.s = self.endpoint.sysreg
        self.hw = self.endpoint.hardware
        self.tables.enable(self.endpoint)
        self.hw.values[self.s.VBAR_EL12] = 0xfffffe00070ad000
        self.hw.values[self.s.ESR_EL12] = 0x11
        self.hw.calls.clear()

    def access(self, register, **kwargs):
        return self.tables.access(self.endpoint, register, **kwargs)

    def instruction(self, imm_tag, mode=4):
        return self.endpoint.feed(self.tables.event(0x5a000000 | imm_tag, mode=mode))

    def enable(self):
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-gxf-config')
        _, after = self.access(self.s.GXF_CONFIG_EL1, read=True, rt=2)
        self.assertEqual(after.regs[2], 1)
        self.access(self.s.GXF_ENTRY_EL1, value=self.ENTRY)
        self.access(self.s.VBAR_GL1, value=self.GL_VECTOR)

    def test_genter_swaps_world_and_gexit_restores_it(self):
        self.enable()
        self.hw.calls.clear()
        before, after = self.instruction(0x6093)
        self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-genter')
        self.assertEqual(after.elr, self.ENTRY)
        self.assertEqual(int(after.spsr) & 0x3cf, 0x3c5)
        self.assertEqual(after.spsr.SS, 1)
        self.assertEqual(self.hw.values[self.s.VBAR_EL12], self.GL_VECTOR)
        self.assertEqual(self.hw.values[self.s.ELR_EL12], before.elr)
        self.assertEqual(self.hw.values[self.s.SPSR_EL12], int(before.spsr))
        self.assertEqual(self.hw.values[self.s.ESR_EL12], 0xfe010003)
        self.assertEqual(list(after.sp)[:2], [before.sp[0], 0])
        _, status = self.access(self.s.GXF_STATUS_EL1, read=True, rt=5)
        self.assertEqual(status.regs[5], 1)
        # Guarded reads of the GL1 bank see the live EL1 bank; writes reach it.
        _, esr = self.access(self.s.ESR_GL1, read=True, rt=6)
        self.assertEqual(esr.regs[6], 0xfe010003)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'guarded-bank-register')
        self.access(self.s.ELR_GL1, value=before.elr+0x40)
        self.assertEqual(self.hw.values[self.s.ELR_EL12], before.elr+0x40)
        self.assertEqual(self.endpoint.report['virtual_gxf']['genter'], 1)
        self.assertTrue(self.endpoint.report['virtual_gxf']['guarded'])
        self.assertFalse(self.endpoint.report['virtual_gxf']['permissions_enforced'])
        # gexit returns to the (modified) link, restores vectors, ESR and SP_EL1.
        _, exited = self.instruction(0x60a0, mode=5)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'virtual-gexit')
        self.assertEqual(exited.elr, before.elr+0x40)
        self.assertEqual(int(exited.spsr) & 0xf, 4)
        self.assertEqual(self.hw.values[self.s.VBAR_EL12], 0xfffffe00070ad000)
        self.assertEqual(self.hw.values[self.s.ESR_EL12], 0x11)
        self.assertEqual(list(exited.sp)[:2], [before.sp[0], before.sp[1]])
        _, status = self.access(self.s.GXF_STATUS_EL1, read=True, rt=5)
        self.assertEqual(status.regs[5], 0)
        self.assertEqual(self.endpoint.report['virtual_gxf']['gexit'], 1)
        # The captured guarded bank is readable afterwards.
        _, esr = self.access(self.s.ESR_GL1, read=True, rt=6)
        self.assertEqual(esr.regs[6], 0xfe010003)

    def test_transitions_fail_closed(self):
        self.instruction(0x6090)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.access(self.s.GXF_CONFIG_EL1, value=1)
        self.instruction(0x6090)  # no entry point staged
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.instruction(0x60a0)  # gexit while not guarded
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-guarded-transition')
        self.endpoint.report.pop('stop_reason')
        self.access(self.s.GXF_CONFIG_EL1, value=3)
        self.assertEqual(self.endpoint.report['stop_reason'], 'unsupported-el2-register')
        self.assertFalse(self.endpoint.report['virtual_gxf']['guarded'])
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, observe_sprr=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.GXF_CONFIG_EL1, value=1)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
        strict.report.pop('stop_reason')
        strict.feed(self.tables.event(0x5a006090))
        self.assertEqual(strict.report['stop_reason'], 'unsupported-exception')


@unittest.skipUnless(os.environ.get('VEL2_CHECKOUT'), 'Set VEL2_CHECKOUT for callback tests')
class StagedHypervisorConfigurationTests(unittest.TestCase):
    """The monitor's EL2 configuration for the level below it is recorded, never applied."""
    def setUp(self):
        self.tables = Tables()
        self.endpoint = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True, stage_el2_config=True)
        self.s = self.endpoint.sysreg
        self.tables.enable(self.endpoint)
        self.endpoint.hardware.calls.clear()

    def test_writes_stage_and_read_back_without_hardware(self):
        for reg in (self.s.AGTCNTRDIR_EL12, self.s.VTTBR_EL2, self.s.VTCR_EL2, self.s.CTRR_LOCK_EL2, self.s.HFGWTR_EL2):
            with self.subTest(register=reg):
                self.tables.access(self.endpoint, reg, value=0x5150, rt=2)
                self.assertEqual(self.endpoint.replies[-1], int(self.endpoint.EXC_RET.HANDLED))
                self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'staged-el2-register')
                _, after = self.tables.access(self.endpoint, reg, read=True, rt=3)
                self.assertEqual(after.regs[3], 0x5150)
        self.assertEqual(self.endpoint.hardware.calls, [])
        self.assertEqual(self.endpoint.report['staged_el2_registers']['VTTBR_EL2'], 0x5150)
        # Unnamed EL2-encoded Apple registers are rewritten and staged with the Apple set.
        self.tables.access(self.endpoint, (3, 4, 15, 10, 0), value=0x77, rt=2)
        self.assertEqual(self.endpoint.report['trace'][-1]['kind'], 'staged-apple-register')
        self.assertEqual(self.endpoint.report['staged_apple_registers']['S3_4_C15_C10_0'], 0x77)
        self.assertEqual(self.endpoint.hardware.calls, [])
        # Translation controls keep their own validated path: a live TCR change still stops.
        self.tables.access(self.endpoint, self.s.TCR_EL2, value=0)
        self.assertEqual(self.endpoint.report['stop_reason'], 'live-translation-control-change')

    def test_default_still_stops(self):
        strict = self.tables.endpoint(os.environ['VEL2_CHECKOUT'], allow_monitor_mmu=True)
        self.tables.enable(strict)
        self.tables.access(strict, self.s.AGTCNTRDIR_EL12, value=3)
        self.assertEqual(strict.report['stop_reason'], 'unsupported-el2-register')
