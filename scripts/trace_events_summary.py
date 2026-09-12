#!/usr/bin/env python3
"""Summarize non-step events of a verified finalized run bundle in one archive pass."""
import argparse
from collections import Counter, deque
from pathlib import Path

from run_manifest import atomic_json, file_identity
from trace_diff import iter_event_archive, load_report

STEP_KIND = 'instruction-step'
DETAIL_FIELDS = ('register', 'read', 'value', 'sysreg', 'effects', 'unsupported_detail')
MAX_CONTEXT = 256
TERMINAL = ('finished', 'failed', 'interrupted')


def summarize_events(events, *, after=0, context=0):
    """Stream events; keep only non-step events plus a bounded step context per event."""
    if type(after) is not int or after < 0:
        raise ValueError('after must be a non-negative event index')
    if type(context) is not int or not 0 <= context <= MAX_CONTEXT:
        raise ValueError(f'context must be between 0 and {MAX_CONTEXT} instruction steps')
    previous = deque(maxlen=context)
    counts, non_step = Counter(), []
    total, selected, steps = 0, 0, 0
    for index, event in enumerate(events):
        total = index+1
        if index < after:
            continue
        selected += 1
        kind = str(event.get('kind', 'unclassified'))
        counts[kind] += 1
        if kind == STEP_KIND:
            steps += 1
            if context:
                previous.append(dict(index=index, event=event))
            continue
        row = dict(index=index, kind=kind, pc=event.get('pc'), steps_since_previous=steps)
        row.update({k: event[k] for k in DETAIL_FIELDS if k in event})
        if context:
            row['context'] = list(previous)
            previous.clear()
        non_step.append(row)
        steps = 0
    if total and after >= total:
        raise ValueError('after index is beyond the archive')
    return dict(total_events=total, after=after, context_steps=context,
                selected=dict(first_index=after if selected else None,
                              last_index=total-1 if selected else None, count=selected),
                kind_counts=dict(sorted(counts.items())),
                non_step_events=non_step, non_step_count=len(non_step),
                non_step_first_index=non_step[0]['index'] if non_step else None,
                non_step_last_index=non_step[-1]['index'] if non_step else None,
                trailing_steps=steps,
                interpretation='Recorded probe events only; step runs count recorded single steps, not guest instructions elided by batching')


def verify_bundle(bundle):
    """Return (manifest, report, archive identity) after checking recorded identities."""
    bundle = Path(bundle)
    manifest = load_report(bundle/'manifest.json')
    report = load_report(bundle/'report.json')
    if not report.get('run_id') or report['run_id'] != manifest.get('run_id'):
        raise ValueError('Run identity mismatch')
    if manifest.get('status') not in TERMINAL or not manifest.get('ended_at'):
        raise ValueError('Requires a finalized bundle')
    capture = manifest.get('capture', {})
    if capture.get('event_archive') != 'events.jsonl':
        raise ValueError('Bundle records no event archive')
    identity = file_identity(bundle/'events.jsonl')
    expected = capture.get('event_archive_identity') or {}
    if any(identity[k] != expected.get(k) for k in ('sha256', 'size')):
        raise ValueError('Archive identity mismatch')
    if type(report.get('trace_total_events')) is not int:
        raise ValueError('Report lacks an integer total event count')
    return manifest, report, identity


def summarize_bundle(bundle, *, after=0, context=0):
    bundle = Path(bundle)
    manifest, report, identity = verify_bundle(bundle)
    result = summarize_events(iter_event_archive(bundle/'events.jsonl'), after=after, context=context)
    if result['total_events'] != report['trace_total_events']:
        raise ValueError('Archive/report event count mismatch')
    result.update(run_id=report['run_id'], bundle=str(bundle.resolve()), archive_identity=identity,
                  capture_complete=bool(manifest['capture'].get('complete')))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('bundle', type=Path, help='Finalized runs/RUN_ID directory')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--after', type=int, default=0, help='Only events at or after this index')
    ap.add_argument('--context', type=int, default=0, help=f'Preceding instruction steps per event, at most {MAX_CONTEXT}')
    a = ap.parse_args()
    result = summarize_bundle(a.bundle, after=a.after, context=a.context)
    atomic_json(a.output, result)
    print(f"Non-step events: {result['non_step_count']} of {result['selected']['count']} selected"
          f" ({result['total_events']} total); kinds: {result['kind_counts']}")


if __name__ == '__main__':
    main()
