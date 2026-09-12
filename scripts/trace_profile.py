#!/usr/bin/env python3
"""Summarize complete event archives without loading full traces or decoding code."""
import argparse
from collections import Counter
from pathlib import Path
from run_manifest import atomic_json, file_identity
from trace_diff import iter_event_archive, load_report


def profile(events, *, top=20, max_pcs=100000, window=65536):
    if not 1 <= top <= 1000 or not 1 <= max_pcs <= 1000000 or window < 1:
        raise ValueError('Invalid profile limits')
    pcs, kinds, windows = {}, Counter(), []
    total, unique_before = 0, 0
    for index, event in enumerate(events):
        total = index+1
        kinds[str(event.get('kind', 'unclassified'))] += 1
        pc = event.get('pc')
        if pc is not None:
            if type(pc) is not int or not 0 <= pc < 1 << 64:
                raise ValueError('Invalid PC')
            if pc not in pcs:
                if len(pcs) >= max_pcs:
                    raise ValueError('Unique PC limit exceeded; no truncated profile emitted')
                pcs[pc] = dict(pc=pc, count=0, first_index=index, last_index=index,
                               first_regs=event.get('regs'), last_regs=event.get('regs'))
            entry = pcs[pc]
            entry['count'] += 1
            entry['last_index'] = index
            entry['last_regs'] = event.get('regs')
        if total % window == 0:
            windows.append(dict(end_index=total, new_pcs=len(pcs)-unique_before, cumulative_pcs=len(pcs)))
            unique_before = len(pcs)
    if total % window:
        windows.append(dict(end_index=total, new_pcs=len(pcs)-unique_before, cumulative_pcs=len(pcs)))
    hottest = sorted(pcs.values(), key=lambda e: (-e['count'], e['pc']))[:top]
    for entry in hottest:
        first, last = entry.pop('first_regs'), entry.pop('last_regs')
        entry['pc_hex'] = hex(entry['pc'])
        entry['register_endpoint_changes'] = [dict(register=i, first=a, last=b)
            for i, (a, b) in enumerate(zip(first, last)) if a != b] if first is not None and last is not None else None
    return dict(schema_version=1, total_events=total, unique_pcs=len(pcs),
                kind_counts=dict(sorted(kinds.items())), hottest_pcs=hottest,
                discovery_windows=windows, window_events=window,
                interpretation='PC frequencies and endpoint register changes only; no loop semantics or boot milestone inferred')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('bundle', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--top', type=int, default=20)
    ap.add_argument('--max-pcs', type=int, default=100000)
    a = ap.parse_args()
    manifest = load_report(a.bundle/'manifest.json')
    report = load_report(a.bundle/'report.json')
    capture = manifest.get('capture', {})
    if manifest.get('run_id') != report.get('run_id') or not manifest.get('ended_at') or not capture.get('complete'):
        raise ValueError('Requires a finalized complete matching run bundle')
    archive = a.bundle/'events.jsonl'
    identity = file_identity(archive)
    expected = capture.get('event_archive_identity', {})
    if any(identity[k] != expected.get(k) for k in ('size', 'sha256')):
        raise ValueError('Archive identity mismatch')
    result = profile(iter_event_archive(archive), top=a.top, max_pcs=a.max_pcs)
    if result['total_events'] != report.get('trace_total_events'):
        raise ValueError('Archive/report count mismatch')
    result.update(run_id=report['run_id'], archive_identity=identity,
                  source_manifest=file_identity(a.bundle/'manifest.json'))
    atomic_json(a.output, result)
    print(f"{result['total_events']} events, {result['unique_pcs']} unique PCs")


if __name__ == '__main__':
    main()
