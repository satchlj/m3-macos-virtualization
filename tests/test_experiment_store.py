"""Immutable ingestion, independent attempts, multiprocess writers and recovery."""
from concurrent.futures import ProcessPoolExecutor
import gzip
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from experiment_store import Catalog
from trace_diff import load_report, compare_reports
from import_experiment_evidence import import_evidence
from experiment_store import digest_file


def ingest_worker(root, source, worker, same_id=False):
    with Catalog(root) as catalog:
        for index in range(8):
            catalog.ingest('test', source, run_id='same' if same_id else f'{worker}-{index}')
    return True


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root/'report.json.gz'
        self.report = dict(scope='test', hardware_executed=False, guest_boot_verified=False,
                           stop_reason='unsupported-system-register',
                           trace=[dict(kind='step', pc=0x1040, regs=[1, 2])],
                           guest_base=0x1000, guest_size=0x1000)
        self.source.write_bytes(gzip.compress(json.dumps(self.report).encode()))
        self.store = Catalog(self.root/'store', create=True)
        self.addCleanup(self.store.close)
        self.addCleanup(self.store.close)
        self.store.define('test', {'hypothesis': 'test only', 'target_os': 'Tahoe'})

    def test_raw_gzip_and_unknown_provenance_preserved(self):
        run = self.store.ingest('test', self.source, run_id='first')
        data = self.store.get(run)
        obj = data['record']['artifacts']['report']
        self.assertEqual(self.store.object_path(obj['sha256']).read_bytes(), self.source.read_bytes())
        self.assertEqual(self.store.report(run), self.report)
        self.assertEqual(data['record']['provenance'], {})
        self.assertFalse(data['summary']['guest_boot_verified'])
        self.assertNotIn('passed', data['summary'])
        self.assertEqual(self.store.verify(), {'runs': 1, 'verified_objects': 1})

    def test_identical_results_are_distinct_attempts_with_deduplicated_bytes(self):
        first, second = [self.store.ingest('test', self.source) for _ in range(2)]
        self.assertNotEqual(first, second)
        self.assertEqual(self.store.verify(), {'runs': 2, 'verified_objects': 1})

    def test_explicit_run_id_makes_import_retries_idempotent(self):
        for _ in range(2):
            self.store.ingest('test', self.source, run_id='same', provenance={'producer_commit': 'abc'})
        self.assertEqual(len(self.store.list_runs()), 1)
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.store.ingest('test', self.source, run_id='same', provenance={'producer_commit': 'changed'})
        self.assertEqual(self.store.get('same')['record']['provenance']['producer_commit'], 'abc')

    def test_definitions_are_immutable_and_unknown_experiments_fail(self):
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.store.define('test', {'target_os': 'Sonoma'})
        with self.assertRaisesRegex(ValueError, 'Unknown experiment'):
            self.store.ingest('missing', self.source)

    def test_attachments_are_opaque_named_and_deduplicated(self):
        artifact = self.root/'frame.zip'
        artifact.write_bytes(b'opaque GPU capture, not a program to run')
        self.store.ingest('test', self.source, run_id='a', artifacts={'frame': artifact, 'copy': artifact})
        self.assertEqual(len(self.store.get('a')['record']['artifacts']), 3)
        self.assertEqual(self.store.verify()['verified_objects'], 2)
        with self.assertRaisesRegex(ValueError, 'reserved'):
            self.store.ingest('test', self.source, artifacts={'report': artifact})

    def test_malformed_report_leaves_no_partial_run(self):
        self.source.write_bytes(b'{"trace": [3]}')
        with self.assertRaisesRegex(ValueError, 'event objects'):
            self.store.ingest('test', self.source)
        self.assertEqual(self.store.list_runs(), [])
        self.assertEqual(self.store.verify()['verified_objects'], 0)

    def test_interrupted_copy_leaves_no_catalog_entry(self):
        with patch('experiment_store.shutil.copyfileobj', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                self.store.ingest('test', self.source)
        self.assertEqual(self.store.list_runs(), [])
        self.assertEqual(list((self.store.root/'objects').iterdir()), [])

    def test_transaction_rolls_back_all_metadata(self):
        self.store.db.execute("CREATE TRIGGER fail_run BEFORE INSERT ON runs BEGIN SELECT RAISE(ABORT, 'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.ingest('test', self.source)
        self.assertEqual(self.store.verify(), {'runs': 0, 'verified_objects': 0})
        self.store.db.execute('DROP TRIGGER fail_run')
        self.store.ingest('test', self.source)
        self.assertEqual(self.store.verify()['runs'], 1)

    def test_corrupt_object_detected_before_read_or_deduplicated_ingest(self):
        self.store.ingest('test', self.source, run_id='a')
        obj = self.store.get('a')['record']['artifacts']['report']
        path = self.store.object_path(obj['sha256'])
        os.chmod(path, 0o644)
        path.write_bytes(b'corrupt')
        for action in (lambda: self.store.report('a'), self.store.verify,
                       lambda: self.store.ingest('test', self.source)):
            with self.assertRaisesRegex(ValueError, 'integrity|corrupt'):
                action()

    def test_backup_is_independent_and_refuses_existing_destination(self):
        self.store.ingest('test', self.source, run_id='a')
        destination = self.root/'snapshot'
        self.assertEqual(self.store.backup(destination)['runs'], 1)
        self.assertTrue((destination/'BACKUP_COMPLETE').is_file())
        self.store.ingest('test', self.source, run_id='b')
        with Catalog(destination) as snapshot:
            self.assertEqual(len(snapshot.list_runs()), 1)
            self.assertEqual(snapshot.report('a'), self.report)
            obj = snapshot.get('a')['record']['artifacts']['report']
            self.assertNotEqual(snapshot.object_path(obj['sha256']).stat().st_ino,
                                self.store.object_path(obj['sha256']).stat().st_ino)
        with self.assertRaises(FileExistsError):
            self.store.backup(destination)

    def test_failed_backup_has_no_completion_marker(self):
        self.store.ingest('test', self.source)
        with patch('experiment_store.shutil.copyfile', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.store.backup(self.root/'partial')
        self.assertFalse((self.root/'partial/BACKUP_COMPLETE').exists())

    def test_parallel_processes_register_all_attempts(self):
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('spawn')) as pool:
            futures = [pool.submit(ingest_worker, self.store.root, self.source, worker) for worker in range(4)]
            self.assertTrue(all(f.result() for f in futures))
        self.assertEqual(self.store.verify(), {'runs': 32, 'verified_objects': 1})

    def test_parallel_retries_do_not_duplicate_one_run(self):
        with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('spawn')) as pool:
            futures = [pool.submit(ingest_worker, self.store.root, self.source, worker, True) for worker in range(4)]
            self.assertTrue(all(f.result() for f in futures))
        self.assertEqual(self.store.verify(), {'runs': 1, 'verified_objects': 1})

    def test_comparison_reports_provenance_mismatch(self):
        self.store.ingest('test', self.source, run_id='a', provenance={'payload': 'one'})
        self.store.ingest('test', self.source, run_id='b', provenance={'payload': 'two'})
        result = self.store.diff('a', 'b')
        self.assertTrue(result['compared_events_equal'])
        self.assertFalse(result['provenance_equal'])
        self.assertFalse(result['provenance_completeness_verified'])

    def test_unknown_schema_and_unknown_catalog_are_not_silently_created(self):
        with self.assertRaisesRegex(ValueError, 'does not exist'):
            Catalog(self.root/'missing')
        with sqlite3.connect(self.root/'future.sqlite') as db:
            db.execute('PRAGMA user_version=999')
        future = self.root/'future'
        future.mkdir()
        (self.root/'future.sqlite').rename(future/'index.sqlite3')
        with self.assertRaisesRegex(ValueError, 'schema version'):
            Catalog(future)

    def test_historical_import_is_verified_idempotent_and_does_not_guess_origin(self):
        self.report['scope'] = 'bounded-sptm-entry'
        self.source.write_bytes(gzip.compress(json.dumps(self.report).encode()))
        (self.root/'sha256.json').write_text(json.dumps({'report.json.gz': digest_file(self.source)[0]}))
        for _ in range(2):
            result = import_evidence(self.store, self.root)
        self.assertEqual(len(self.store.list_runs()), 1)
        record = self.store.get(result['imported_or_existing_runs'][0])['record']
        self.assertEqual(record['provenance']['kind'], 'historical-import')
        self.assertNotIn('producer_commit', record['provenance'])

    def test_evidence_mismatch_prevents_all_registration(self):
        (self.root/'sha256.json').write_text(json.dumps({'report.json.gz': '0'*64}))
        with self.assertRaisesRegex(ValueError, 'checksum'):
            import_evidence(self.store, self.root)
        self.assertEqual(self.store.list_runs(), [])


class TraceDiffTests(unittest.TestCase):
    def report(self, base=0x1000, value=1):
        return dict(guest_base=base, guest_size=0x1000, trace=[
            dict(kind='step', pc=base+64, regs=[value], far=0),
            dict(kind='stop', pc=base+68, sysreg={'encoding': [2,0,0,2,2], 'read': True, 'rt': 12, 'value': value})])

    def test_exact_comparison_preserves_values_and_addresses(self):
        result = compare_reports(self.report(), self.report(value=2))
        self.assertFalse(result['compared_events_equal'])
        self.assertEqual(result['first_divergence']['index'], 0)
        self.assertEqual(result['exclusions'], [])

    def test_control_flow_only_normalizes_known_guest_pc_and_is_explicitly_lossy(self):
        result = compare_reports(self.report(), self.report(0x9000, 2), 'control-flow-v1')
        self.assertTrue(result['compared_events_equal'])
        self.assertIn('register values', result['exclusions'])
        self.assertFalse(result['full_state_equivalence_claimed'])

    def test_unmapped_virtual_pc_is_never_guessed_or_relocated(self):
        a, b = self.report(), self.report()
        a['trace'][0]['pc'], b['trace'][0]['pc'] = 0xffff800000001000, 0xffff800000002000
        self.assertFalse(compare_reports(a, b, 'control-flow-v1')['compared_events_equal'])

    def test_missing_trace_is_not_identical_to_empty_trace(self):
        with self.assertRaisesRegex(ValueError, 'missing'):
            compare_reports({}, {'trace': []})

    def test_appended_events_and_outcome_changes_remain_visible(self):
        a, b = self.report(), self.report()
        b['trace'].append({'kind': 'fault'})
        b['stop_reason'] = 'fault'
        result = compare_reports(a, b)
        self.assertEqual(result['common_prefix_events'], 2)
        self.assertIsNone(result['first_divergence']['left'])
        self.assertIn('stop_reason', result['outcome_differences'])
        self.assertEqual(result['kind_counts']['right']['fault'], 1)

    def test_event_dictionary_key_order_does_not_create_difference(self):
        self.assertTrue(compare_reports({'trace': [{'a': 1, 'b': 2}]},
                                        {'trace': [{'b': 2, 'a': 1}]})['compared_events_equal'])

    def test_reader_rejects_nonfinite_and_oversized_json(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)/'report'
            path.write_text('{"value":NaN}')
            with self.assertRaises(ValueError):
                load_report(path)
            path.write_bytes(gzip.compress(b'{"trace":[]}'))
            with patch('trace_diff.MAX_REPORT_BYTES', 2), self.assertRaisesRegex(ValueError, 'limit'):
                load_report(path)
