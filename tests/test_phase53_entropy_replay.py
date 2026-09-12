"""Focused tests for the pinned Phase 5.3 guest-ADT entropy replay."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

from phase53_entropy_replay import (CONFIG_EVIDENCE_FIELD, PROPERTY_SPECS,
                                    SOURCE_SHA256, config_evidence,
                                    materialize_config_evidence,
                                    replay_entropy_properties)
from run_probe_pipeline import probe_command, summarize_report


class Node:
    def __init__(self, properties):
        self._properties = dict(properties)


class Tree:
    def __init__(self, properties):
        self.chosen = Node(properties)

    def __getitem__(self, path):
        if path != '/chosen':
            raise KeyError(path)
        return self.chosen


def values(fill, nonce):
    return {
        'name': 'chosen',
        'random-seed': bytes([fill]) * PROPERTY_SPECS['random-seed'][1],
        'cl4-entropy': bytes([fill + 1]) * PROPERTY_SPECS['cl4-entropy'][1],
        'boot-nonce': nonce,
        'unrelated': b'preserve-me',
    }


class EntropyReplayTests(unittest.TestCase):
    def test_replays_exactly_three_properties_and_records_hashes(self):
        target = Tree(values(1, 2))
        source = Tree(values(7, 8))
        unrelated = target.chosen._properties['unrelated']
        identity = {'path': '/source/attempt-108.adt',
                    'sha256': SOURCE_SHA256, 'size': 445024}
        report = replay_entropy_properties(target, source, identity)
        self.assertEqual(report['property_count'], 3)
        self.assertFalse(report['other_properties_modified_by_replay'])
        self.assertEqual(target.chosen._properties['unrelated'], unrelated)
        self.assertEqual(target.chosen._properties['name'], 'chosen')
        for name in PROPERTY_SPECS:
            self.assertEqual(target.chosen._properties[name],
                             source.chosen._properties[name])
            record = report['properties'][name]
            self.assertTrue(record['changed'])
            self.assertEqual(record['after_sha256'], record['source_sha256'])
            self.assertNotEqual(record['before_sha256'], record['after_sha256'])
        self.assertEqual(report['source'], identity)

    def test_missing_or_malformed_property_fails_closed(self):
        good = values(1, 2)
        for bad in (
                {**good, 'random-seed': b'short'},
                {key: value for key, value in good.items() if key != 'boot-nonce'},
                {**good, 'boot-nonce': -1}):
            target = Tree(good)
            before = dict(target.chosen._properties)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                replay_entropy_properties(target, Tree(bad), {})
            self.assertEqual(target.chosen._properties, before)

    def test_pipeline_config_materializes_pinned_evidence_but_not_cli_argument(self):
        base = dict(payload='/payload', checkout='/checkout', device='/dev/test',
                    steps=16, free_run=True, real_guarded=True, hang_budget=120,
                    native_handoff=True, xnu_steps=64, xnu_run=True,
                    xnu_txm_handler_boundary='cmd1-completion-trace',
                    xnu_txm_sstep_fast_path=True,
                    xnu_phase53_allocation_trace=True,
                    xnu_phase53_retype_survey=True,
                    xnu_phase53_adt_entropy_replay=True)
        config = materialize_config_evidence(base)
        self.assertEqual(config[CONFIG_EVIDENCE_FIELD], config_evidence())
        command = probe_command(config, Path('/output'), True)
        self.assertIn('--xnu-phase53-adt-entropy-replay', command)
        self.assertFalse(any(CONFIG_EVIDENCE_FIELD.replace('_', '-') in part
                             for part in command))
        with self.assertRaisesRegex(ValueError, 'pinned Attempt108'):
            materialize_config_evidence({**config, CONFIG_EVIDENCE_FIELD: {}})
        with self.assertRaisesRegex(ValueError, 'requires xnu_phase53_retype_survey'):
            probe_command({**base, 'xnu_phase53_retype_survey': False},
                          Path('/output'), True)

    def test_summary_retains_replay_evidence(self):
        evidence = {'requested': True, 'source': {'sha256': SOURCE_SHA256}}
        summary = summarize_report({
            'trace': [], 'xnu_phase53_adt_entropy_replay': evidence})
        self.assertIs(summary['xnu_phase53_adt_entropy_replay'], evidence)


if __name__ == '__main__':
    unittest.main()
