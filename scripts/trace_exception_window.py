#!/usr/bin/env python3
"""Locate the first guest vector entry in a verified complete trace archive."""
import argparse
from collections import deque
from pathlib import Path
from run_manifest import atomic_json, file_identity
from trace_diff import iter_event_archive, load_report


def exception_window(events, vector, *, before=64, after=16):
    if not isinstance(vector, int) or vector < 0 or vector % 2048 or vector+2048 > 1 << 64:
        raise ValueError('Invalid guest vector base')
    if not 0 <= before <= 4096 or not 0 <= after <= 4096:
        raise ValueError('Invalid context bounds')
    previous, context = deque(maxlen=before), []
    first, count = None, 0
    for index, event in enumerate(events):
        count = index+1
        row = dict(index=index, event=event)
        pc = event.get('pc')
        if first is None:
            if isinstance(pc, int) and vector <= pc < vector+2048:
                first = index
                context = list(previous)+[row]
            else:
                previous.append(row)
        elif index <= first+after:
            context.append(row)
    return dict(total_events=count, vector_base=vector, first_vector_index=first,
                context=context, interpretation='First recorded PC in the vector table; exception cause requires matching guest diagnostics')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('bundle', type=Path)
    ap.add_argument('diagnostics', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    manifest = load_report(a.bundle/'manifest.json')
    report = load_report(a.bundle/'report.json')
    diagnostics = load_report(a.diagnostics)
    if not report.get('run_id') or report['run_id'] != manifest.get('run_id') or report['run_id'] != diagnostics.get('run_id'):
        raise ValueError('Run identity mismatch')
    if not manifest.get('ended_at') or not manifest.get('capture', {}).get('complete'):
        raise ValueError('Requires complete finalized trace')
    identity = file_identity(a.bundle/'events.jsonl')
    expected = manifest['capture'].get('event_archive_identity', {})
    if any(identity[k] != expected.get(k) for k in ('sha256', 'size')):
        raise ValueError('Archive identity mismatch')
    expected_report = diagnostics.get('source_report', {})
    actual_report = file_identity(a.bundle/'report.json')
    if any(actual_report[k] != expected_report.get(k) for k in ('sha256', 'size')):
        raise ValueError('Diagnostic source report mismatch')
    result = exception_window(iter_event_archive(a.bundle/'events.jsonl'), diagnostics['exception']['VBAR_EL12'])
    if result['total_events'] != report.get('trace_total_events'):
        raise ValueError('Archive/report event count mismatch')
    result.update(run_id=report['run_id'], exception=diagnostics['exception'],
                  archive_identity=identity, diagnostics_identity=file_identity(a.diagnostics))
    atomic_json(a.output, result)
    print('First guest vector index:', result['first_vector_index'])


if __name__ == '__main__':
    main()
