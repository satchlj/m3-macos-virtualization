#!/usr/bin/env python3
"""Recover early XNU character output from observed SPTM dispatch calls."""
import argparse
from pathlib import Path
from trace_diff import iter_event_archive, load_report
from trace_events_summary import verify_bundle

DISPATCH_READ_PC = 0xfffffe00070a452c


def console_bytes(events):
    for event in events:
        regs = event.get('regs', [])
        if (event.get('pc') == DISPATCH_READ_PC
                and event.get('kind') == 'real-guarded-redirect'
                and event.get('register') == 'ESR_GL1' and event.get('read') is True
                and len(regs) > 16 and regs[16] == 0x2d
                and type(regs[0]) is int and 0 <= regs[0] <= 255):
            yield regs[0]


def recover_console(report, runs_dir):
    """Recover bytes from the verified run archive, or a complete report trace."""
    run_id = report.get('run_id')
    if not isinstance(run_id, str) or not run_id:
        raise ValueError('Report lacks a run_id; console source is unavailable')
    bundle = Path(runs_dir) / run_id
    archive = bundle / 'events.jsonl'
    if archive.exists():
        manifest, archived_report, identity = verify_bundle(bundle)
        if archived_report.get('run_id') != run_id:
            raise ValueError('Selected archive run identity differs from report')
        count = 0
        def counted_events():
            nonlocal count
            for event in iter_event_archive(archive):
                count += 1
                yield event
        data = bytes(console_bytes(counted_events()))
        expected = report.get('trace_total_events')
        if type(expected) is not int or count != expected:
            raise ValueError('Event archive count differs from report')
        return data, dict(source='verified-event-archive', run_id=run_id,
                          archive_identity=identity, total_events=count,
                          capture_complete=bool(manifest['capture'].get('complete')))
    trace = report.get('trace')
    if report.get('trace_start_index', 0) == 0 and isinstance(trace, list):
        expected = report.get('trace_total_events', len(trace))
        if type(expected) is not int or expected != len(trace):
            raise ValueError('Complete report trace count differs from report')
        return bytes(console_bytes(trace)), dict(
            source='complete-report-trace', run_id=run_id, total_events=len(trace))
    raise ValueError('Full event archive is unavailable for rolling report')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path, help='report JSON or full indexed events.jsonl')
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    if args.source.suffix == '.jsonl':
        events = iter_event_archive(args.source)
    else:
        report = load_report(args.source)
        if report.get('trace_start_index', 0):
            ap.error('Report is a rolling window; use the full events.jsonl archive')
        events = report.get('trace', [])
    data = bytes(console_bytes(events))
    if args.output:
        args.output.write_bytes(data)
    else:
        print(data.decode('utf-8', errors='backslashreplace'), end='')


if __name__ == '__main__':
    main()
