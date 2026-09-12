#!/usr/bin/env python3
"""Classify verified XNU/SPTM MAP_PAGE progress without making a loop claim."""
import argparse
from collections import Counter
from pathlib import Path

from run_manifest import atomic_json
from trace_diff import iter_event_archive
from trace_events_summary import verify_bundle


MAP_SERVICE_PC = 0xFFFFFE00070A452C
PAGE_SIZE = 0x4000


def _hex(value):
    return hex(value) if type(value) is int else value


def _map_row(index, event):
    regs = event.get('regs')
    if (event.get('pc') != MAP_SERVICE_PC or not isinstance(regs, list)
            or len(regs) <= 16 or regs[16] != 2
            or any(type(regs[i]) is not int for i in (0, 1, 2))):
        return None
    return dict(index=index, root=regs[0], va=regs[1],
                pte_pa=regs[2] & ~(PAGE_SIZE - 1),
                flags=regs[2] & (PAGE_SIZE - 1))


def _fixed_delta_segments(rows, minimum):
    if type(minimum) is not int or minimum < 2:
        raise ValueError('minimum segment length must be an integer of at least 2')
    if len(rows) < minimum:
        return []
    segments = []
    start = 0
    delta = None
    for i in range(1, len(rows)):
        current = (rows[i]['va'] - rows[i - 1]['va'],
                   rows[i]['pte_pa'] - rows[i - 1]['pte_pa'],
                   rows[i]['flags'] - rows[i - 1]['flags'])
        if delta is None:
            delta = current
        elif current != delta:
            if i - start >= minimum:
                segments.append(_segment(rows, start, i - 1, delta))
            start, delta = i - 1, current
    if len(rows) - start >= minimum:
        segments.append(_segment(rows, start, len(rows) - 1, delta))
    return segments


def _segment(rows, start, end, delta):
    first, last = rows[start], rows[end]
    return dict(count=end - start + 1,
                first_index=first['index'], last_index=last['index'],
                first_va=first['va'], last_va=last['va'],
                first_pte_pa=first['pte_pa'], last_pte_pa=last['pte_pa'],
                flags=first['flags'],
                delta_va=delta[0], delta_pte_pa=delta[1], delta_flags=delta[2])


def _terminal_page_segment(rows):
    if not rows:
        return None
    start = len(rows) - 1
    while start and (rows[start]['va'] - rows[start - 1]['va'] == PAGE_SIZE
                     and rows[start]['pte_pa'] - rows[start - 1]['pte_pa'] == PAGE_SIZE
                     and rows[start]['flags'] == rows[start - 1]['flags']):
        start -= 1
    return _segment(rows, start, len(rows) - 1,
                    (PAGE_SIZE, PAGE_SIZE, 0))


def _terminal_va_segment(rows):
    if not rows:
        return None
    start = len(rows) - 1
    while start and (rows[start]['root'] == rows[start - 1]['root']
                     and rows[start]['va'] - rows[start - 1]['va'] == PAGE_SIZE
                     and rows[start]['flags'] == rows[start - 1]['flags']):
        start -= 1
    first, last = rows[start], rows[-1]
    return dict(count=len(rows) - start,
                first_index=first['index'], last_index=last['index'],
                root=first['root'], first_va=first['va'], last_va=last['va'],
                first_pte_pa=first['pte_pa'], last_pte_pa=last['pte_pa'],
                flags=first['flags'], delta_va=PAGE_SIZE,
                pte_deltas=[rows[i]['pte_pa'] - rows[i - 1]['pte_pa']
                            for i in range(start + 1, len(rows))])


def classify_bundle(bundle, *, minimum_segment=4):
    bundle = Path(bundle)
    manifest, report, identity = verify_bundle(bundle)
    capture = manifest.get('capture', {})
    if manifest.get('status') != 'finished' or not capture.get('complete'):
        raise ValueError('Requires a finished, complete event capture')

    rows, final_event, total = [], None, 0
    for index, event in enumerate(iter_event_archive(bundle / 'events.jsonl')):
        total = index + 1
        final_event = event
        row = _map_row(index, event)
        if row is not None:
            rows.append(row)
    if total != report.get('trace_total_events'):
        raise ValueError('Archive/report event count mismatch')

    tuples = [(row['root'], row['va'], row['pte_pa'], row['flags']) for row in rows]
    repetitions = Counter(tuples)
    terminal = _terminal_page_segment(rows)
    terminal_va = _terminal_va_segment(rows)
    result = dict(
        schema_version=1,
        run_id=report['run_id'],
        bundle=str(bundle.resolve()),
        archive_identity=identity,
        outcome=dict(
            stop_reason=report.get('stop_reason'),
            final_event=final_event,
            guest_returned=report.get('guest_returned'),
            proxy_alive_after_exit=report.get('proxy_alive_after_exit'),
            cleanup_error=report.get('cleanup_error'),
            watchdog=report.get('watchdog'),
            xnu_pperm_guest_window=report.get('xnu_pperm_guest_window'),
            xnu_pperm_guest_window_cleanup=report.get('xnu_pperm_guest_window_cleanup')),
        maps=dict(
            service_pc=MAP_SERVICE_PC,
            total_calls=len(rows),
            unique_tuples=len(repetitions),
            repeated_tuples=sum(count > 1 for count in repetitions.values()),
            maximum_tuple_repetitions=max(repetitions.values(), default=0),
            first=rows[0] if rows else None,
            last=rows[-1] if rows else None,
            events_after_last_map=(total - 1 - rows[-1]['index']) if rows else None,
            terminal_plus_page_segment=terminal,
            terminal_va_page_segment=terminal_va,
            fixed_delta_segments=_fixed_delta_segments(rows, minimum_segment)),
        interpretation=dict(
            loop_classification='not-demonstrated',
            reason=('This tool reports verified tuple repetition and progress only; '
                    'a watchdog stop, repeated PC, or repeated address alone is not loop evidence.'),
            terminal_progress_observed=bool(terminal_va and terminal_va['count'] >= 2),
            full_boot_established=False))
    return result


def _print_summary(result):
    outcome, maps = result['outcome'], result['maps']
    final = outcome['final_event'] or {}
    terminal = maps['terminal_plus_page_segment']
    terminal_va = maps['terminal_va_page_segment']
    print('run', result['run_id'], 'outcome', outcome['stop_reason'],
          'final', final.get('kind'), _hex(final.get('pc')))
    print('maps', maps['total_calls'], 'unique', maps['unique_tuples'],
          'repeated', maps['repeated_tuples'], 'max-repetitions', maps['maximum_tuple_repetitions'])
    if terminal:
        print('terminal +0x4000 segment', terminal['count'],
              _hex(terminal['first_va']), _hex(terminal['last_va']),
              'events-after', maps['events_after_last_map'])
    if terminal_va and (not terminal or terminal_va['count'] != terminal['count']):
        print('terminal +0x4000 VA segment', terminal_va['count'],
              _hex(terminal_va['first_va']), _hex(terminal_va['last_va']),
              'nonuniform-PTE-deltas')
    print('loop', result['interpretation']['loop_classification'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('bundle', type=Path, help='Finalized runs/RUN_ID directory')
    ap.add_argument('--minimum-segment', type=int, default=4,
                    help='Minimum map count for fixed-delta segment reporting (default: 4)')
    ap.add_argument('--output', type=Path, help='Optional atomic JSON output')
    args = ap.parse_args()
    result = classify_bundle(args.bundle, minimum_segment=args.minimum_segment)
    if args.output:
        atomic_json(args.output, result)
    _print_summary(result)


if __name__ == '__main__':
    main()
