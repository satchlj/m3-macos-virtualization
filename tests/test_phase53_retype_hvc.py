# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Focused tests for the source-pinned Phase 5.3 retype HVC helper."""
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from phase53_retype_hvc import (GENTER_SITE, MAX_RETYPE_CALLS, POST_SITE, PRE_SITE,
                                RETYPE_HVC_SITES,
                                RetypeHvcStateMachine,
                                source_pinned_rewrite_plan,
                                verify_hvc_rewrites)
from run_probe_pipeline import probe_command, summarize_report
from sptm_entry_probe import patch_xnu_phase53_retype_hvc


class Phase53RetypeHvcTests(unittest.TestCase):
    @staticmethod
    def pipeline_config(**updates):
        config = dict(
            payload='/payload', checkout='/checkout', device='/device',
            steps=16, free_run=True, real_guarded=True, hang_budget=90,
            native_handoff=True, xnu_steps=64, xnu_run=True,
            xnu_gl1_fast_redirect=True,
            xnu_txm_handler_boundary='cmd1-completion-trace',
            xnu_txm_sstep_fast_path=True,
            xnu_phase53_allocation_trace=True,
            xnu_phase53_retype_survey=True,
            xnu_phase53_retype_hvc_fast_path=True,
        )
        config.update(updates)
        return config

    def test_exact_source_pins_and_hvc_rewrite_words(self):
        self.assertEqual(PRE_SITE.runtime_pc, 0xfffffe002bf7a4b8)
        self.assertEqual(PRE_SITE.post_hvc_pc, 0xfffffe002bf7a4bc)
        self.assertEqual(PRE_SITE.linked_pc, 0xfffffe000bf7a4b8)
        self.assertEqual(PRE_SITE.source_word, 0x910003fd)
        self.assertEqual(PRE_SITE.hvc_immediate, 0x6130)
        self.assertEqual(PRE_SITE.hvc_word, 0xd40c2602)
        self.assertEqual(POST_SITE.runtime_pc, 0xfffffe002bf7a4cc)
        self.assertEqual(POST_SITE.post_hvc_pc, 0xfffffe002bf7a4d0)
        self.assertEqual(POST_SITE.linked_pc, 0xfffffe000bf7a4cc)
        self.assertEqual(POST_SITE.source_word, 0x910003bf)
        self.assertEqual(POST_SITE.hvc_immediate, 0x6131)
        self.assertEqual(POST_SITE.hvc_word, 0xd40c2622)
        self.assertEqual(GENTER_SITE.runtime_pc, 0xfffffe002bf7a4c0)
        self.assertEqual(GENTER_SITE.post_hvc_pc, 0xfffffe002bf7a4c4)
        self.assertEqual(GENTER_SITE.linked_pc, 0xfffffe000bf7a4c0)
        self.assertEqual(GENTER_SITE.source_word, 0xd2800030)
        self.assertEqual(GENTER_SITE.hvc_immediate, 0x6132)
        self.assertEqual(GENTER_SITE.hvc_word, 0xd40c2642)

        source = {site.linked_pc: site.source_word
                  for site in (PRE_SITE, GENTER_SITE, POST_SITE)}
        plan = source_pinned_rewrite_plan(source.__getitem__)
        self.assertEqual(plan, (
            (PRE_SITE.linked_pc, PRE_SITE.source_word, PRE_SITE.hvc_word),
            (GENTER_SITE.linked_pc, GENTER_SITE.source_word,
             GENTER_SITE.hvc_word),
            (POST_SITE.linked_pc, POST_SITE.source_word, POST_SITE.hvc_word),
        ))
        linked_rewritten = {address: replacement
                            for address, _, replacement in plan}
        self.assertTrue(verify_hvc_rewrites(linked_rewritten.__getitem__))
        runtime_rewritten = {
            PRE_SITE.runtime_pc: PRE_SITE.hvc_word,
            GENTER_SITE.runtime_pc: GENTER_SITE.hvc_word,
            POST_SITE.runtime_pc: POST_SITE.hvc_word,
        }
        self.assertTrue(verify_hvc_rewrites(runtime_rewritten.__getitem__,
                                            runtime=True))

    def test_source_or_rewrite_drift_fails_closed(self):
        good = {site.linked_pc: site.source_word
                for site in (PRE_SITE, GENTER_SITE, POST_SITE)}
        for site in (PRE_SITE, GENTER_SITE, POST_SITE):
            drifted = dict(good)
            drifted[site.linked_pc] ^= 1
            with self.subTest(source_phase=site.phase), \
                    self.assertRaisesRegex(ValueError, site.phase + ' source drift'):
                source_pinned_rewrite_plan(drifted.__getitem__)

        rewrites = {site.linked_pc: site.hvc_word
                    for site in (PRE_SITE, GENTER_SITE, POST_SITE)}
        rewrites[POST_SITE.linked_pc] ^= 1
        with self.assertRaisesRegex(ValueError, 'POST HVC rewrite mismatch'):
            verify_hvc_rewrites(rewrites.__getitem__)

    def test_kernel_chunk_patch_is_atomic_and_source_pinned(self):
        segment = {'va': PRE_SITE.linked_pc - 8}
        size = POST_SITE.linked_pc - segment['va'] + 12
        chunk = bytearray(b'\xa5' * size)
        for site in RETYPE_HVC_SITES:
            offset = site.linked_pc - segment['va']
            chunk[offset:offset + 4] = site.source_word.to_bytes(4, 'little')
        original = bytes(chunk)
        patched, records = patch_xnu_phase53_retype_hvc(
            original, segment, True)
        self.assertEqual(len(records), 3)
        for site in RETYPE_HVC_SITES:
            offset = site.linked_pc - segment['va']
            self.assertEqual(int.from_bytes(patched[offset:offset + 4], 'little'),
                             site.hvc_word)
        restored = bytearray(patched)
        for site in RETYPE_HVC_SITES:
            offset = site.linked_pc - segment['va']
            restored[offset:offset + 4] = original[offset:offset + 4]
        self.assertEqual(bytes(restored), original)

        drifted = bytearray(original)
        offset = GENTER_SITE.linked_pc - segment['va']
        drifted[offset] ^= 1
        with self.assertRaisesRegex(ValueError, 'GENTER source drift'):
            patch_xnu_phase53_retype_hvc(bytes(drifted), segment, True)
        self.assertEqual(patch_xnu_phase53_retype_hvc(
            original, segment, False), (original, []))

    def test_state_machine_requires_strict_three_phase_ordering(self):
        machine = RetypeHvcStateMachine(max_calls=2)
        first = machine.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)
        self.assertEqual(first['call_index'], 1)
        self.assertEqual(first['next_phase'], 'GENTER')
        middle = machine.observe(GENTER_SITE.post_hvc_pc,
                                 GENTER_SITE.hvc_word)
        self.assertEqual(middle['next_phase'], 'POST')
        completed = machine.observe(POST_SITE.post_hvc_pc, POST_SITE.hvc_word)
        self.assertEqual(completed['completed_calls'], 1)
        self.assertEqual(completed['next_phase'], 'PRE')

        machine.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)
        machine.observe(GENTER_SITE.post_hvc_pc, GENTER_SITE.hvc_word)
        terminal = machine.observe(POST_SITE.post_hvc_pc, POST_SITE.hvc_word)
        self.assertTrue(terminal['at_limit'])
        self.assertEqual(machine.snapshot()['completed_calls'], 2)

        for bad_sequence in (
                ((POST_SITE.post_hvc_pc, POST_SITE.hvc_word),),
                ((PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word),
                 (PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word))):
            bad = RetypeHvcStateMachine()
            with self.subTest(sequence=bad_sequence), self.assertRaisesRegex(
                    ValueError, 'order violation'):
                for observation in bad_sequence:
                    bad.observe(*observation)
            self.assertTrue(bad.snapshot()['failed'])
            with self.assertRaisesRegex(RuntimeError, 'already failed closed'):
                bad.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)

    def test_state_machine_rejects_pc_word_drift_and_call_65(self):
        for pc, word, message in (
                (PRE_SITE.post_hvc_pc + 4, PRE_SITE.hvc_word, 'post-PC drift'),
                (PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word ^ 1, 'word drift')):
            machine = RetypeHvcStateMachine()
            with self.subTest(message=message), self.assertRaisesRegex(
                    ValueError, message):
                machine.observe(pc, word)
            self.assertTrue(machine.snapshot()['failed'])

        machine = RetypeHvcStateMachine()
        for _ in range(MAX_RETYPE_CALLS):
            machine.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)
            machine.observe(GENTER_SITE.post_hvc_pc, GENTER_SITE.hvc_word)
            machine.observe(POST_SITE.post_hvc_pc, POST_SITE.hvc_word)
        self.assertEqual(machine.snapshot()['completed_calls'], 64)
        with self.assertRaisesRegex(ValueError, 'call limit reached'):
            machine.observe(PRE_SITE.post_hvc_pc, PRE_SITE.hvc_word)
        self.assertTrue(machine.snapshot()['failed'])

    def test_limit_configuration_is_bounded_by_hard_cap(self):
        for value in (0, -1, MAX_RETYPE_CALLS + 1, 1.0, True):
            with self.subTest(value=value), self.assertRaisesRegex(
                    ValueError, r'\[1, 64\]'):
                RetypeHvcStateMachine(value)

    def test_pipeline_emits_option_and_validates_survey_dependency(self):
        command = probe_command(self.pipeline_config(), Path('/output'), False)
        self.assertIn('--xnu-phase53-retype-hvc-fast-path', command)

        with self.assertRaisesRegex(
                ValueError,
                'xnu_phase53_retype_hvc_fast_path requires '
                'xnu_phase53_retype_survey and xnu_gl1_fast_redirect'):
            probe_command(self.pipeline_config(
                xnu_phase53_retype_survey=False), Path('/output'), False)
        with self.assertRaisesRegex(
                ValueError, 'xnu_gl1_fast_redirect'):
            probe_command(self.pipeline_config(
                xnu_gl1_fast_redirect=False), Path('/output'), False)
        with self.assertRaisesRegex(
                ValueError, 'Expected Boolean configuration'):
            probe_command(self.pipeline_config(
                xnu_phase53_retype_hvc_fast_path=1), Path('/output'), False)

    def test_pipeline_summary_retains_fast_path_evidence(self):
        evidence = {
            'requested': True,
            'enabled': True,
            'completed_calls': 7,
            'expected_phase': 'PRE',
        }
        summary = summarize_report({
            'trace': [], 'xnu_phase53_retype_hvc_fast_path': evidence})
        self.assertIs(summary['xnu_phase53_retype_hvc_fast_path'], evidence)


if __name__ == '__main__':
    unittest.main()
