import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from trace_diff import iter_event_archive,compare_event_streams
from experiment_store import Catalog


class EventArchiveTests(unittest.TestCase):
    def test_stream_vs_full_report_catalog_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[{'pc':i,'kind':'step'}for i in range(20)]
            (root/'events').write_text(''.join(json.dumps({'index':i,'event':e})+'\n'for i,e in enumerate(events)))
            (root/'window').write_text(json.dumps({'trace':events[-2:],'trace_start_index':18,'trace_total_events':20}))
            (root/'full').write_text(json.dumps({'trace':events}))
            with Catalog(root/'store',create=True) as c:
                c.define('test',{})
                a=c.ingest('test',root/'window',artifacts={'events':root/'events'})
                b=c.ingest('test',root/'full')
                result=c.diff(a,b)
                self.assertTrue(result['compared_events_equal'])
                self.assertTrue(result['complete_traces_compared'])
                self.assertEqual(result['common_prefix_events'],20)

    def test_partial_duplicate_and_missing_records_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'events'
            for text in ['{"index":0,"event":{}}', '{"index":1,"event":{}}\n',
                         '{"index":0,"event":{}}\n{"index":0,"event":{}}\n']:
                path.write_text(text)
                with self.assertRaises(ValueError):list(iter_event_archive(path))
        with self.assertRaisesRegex(ValueError,'count differs'):
            compare_event_streams({'trace_total_events':2},{},iter([{}]),iter([]))

    def test_stream_first_divergence_and_tail_counts(self):
        r=compare_event_streams({}, {}, iter([{'pc':1},{'pc':2}]),iter([{'pc':1},{'pc':3},{}]))
        self.assertEqual(r['first_divergence']['index'],1)
        self.assertEqual(r['event_counts'],{'left':2,'right':3})
