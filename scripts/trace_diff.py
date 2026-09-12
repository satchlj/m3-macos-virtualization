"""Versioned, conservative comparisons of bounded JSON trace reports."""
from collections import Counter
import copy
import gzip
import json

MAX_REPORT_BYTES = 256 * 1024 * 1024


def load_report(path):
    with open(path, 'rb') as raw:
        magic = raw.read(2)
        raw.seek(0)
        if magic == b'\x1f\x8b':
            with gzip.GzipFile(fileobj=raw) as decoded:
                data = decoded.read(MAX_REPORT_BYTES+1)
        else:
            data = raw.read(MAX_REPORT_BYTES+1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError('Report exceeds bounded JSON reader limit')
    result = json.loads(data, parse_constant=lambda s: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    if not isinstance(result, dict):
        raise ValueError('Report must be a JSON object')
    if 'trace' in result and (not isinstance(result['trace'], list) or
                              any(not isinstance(e, dict) for e in result['trace'])):
        raise ValueError('Trace must be a list of event objects')
    return result


def event_view(event, report, mode):
    if mode == 'exact-v1':
        return event
    if mode != 'control-flow-v1':
        raise ValueError('Unknown trace comparison mode')
    # A deliberately lossy view: never call matching control flow equivalent state.
    fields = ('reason', 'code', 'kind', 'pc', 'esr', 'register', 'read')
    value = {k: copy.deepcopy(event[k]) for k in fields if k in event}
    if isinstance(event.get('sysreg'), dict):
        value['sysreg'] = {k: event['sysreg'][k] for k in ('encoding', 'read', 'rt') if k in event['sysreg']}
    pc, base, size = value.get('pc'), report.get('guest_base'), report.get('guest_size')
    if all(type(n) is int for n in (pc, base, size)) and 0 <= base < base+size <= 1 << 64 and base <= pc < base+size:
        value['pc'] = {'guest_physical_offset': pc-base}
    # High virtual addresses stay exact: there is no verified slide mapping here.
    return value


def compare_reports(left, right, mode='exact-v1'):
    if mode not in ('exact-v1', 'control-flow-v1'):
        raise ValueError('Unknown trace comparison mode')
    if 'trace' not in left or 'trace' not in right:
        raise ValueError('Both reports must contain a trace; missing is not empty')
    if left.get('trace_start_index', 0) != right.get('trace_start_index', 0):
        raise ValueError('Trace windows start at different logical indices; compare event archives instead')
    a, b = left['trace'], right['trace']
    first = None
    prefix = 0
    for index in range(max(len(a), len(b))):
        av = event_view(a[index], left, mode) if index < len(a) else None
        bv = event_view(b[index], right, mode) if index < len(b) else None
        if av != bv:
            first = dict(index=index, left=av, right=bv)
            break
        prefix += 1
    counts = lambda events: dict(sorted(Counter(str(e.get('kind', 'unclassified')) for e in events).items()))
    keys = ('scope', 'stop_reason', 'error', 'cleanup_error', 'hardware_executed',
            'guest_boot_verified', 'proxy_alive_after_exit', 'steps_limit')
    differences = {key: {'left': left.get(key), 'right': right.get(key)}
                   for key in keys if (key in left) != (key in right) or left.get(key) != right.get(key)}
    return dict(schema_version=1, mode=mode, trace_start_index=left.get('trace_start_index', 0),
                complete_traces_compared=not left.get('trace_start_index', 0) and not right.get('trace_start_index', 0), compared_events_equal=first is None,
                full_state_equivalence_claimed=False, common_prefix_events=prefix,
                first_divergence=first, event_counts={'left': len(a), 'right': len(b)},
                kind_counts={'left': counts(a), 'right': counts(b)},
                outcome_differences=differences,
                exclusions=[] if mode == 'exact-v1' else [
                    'register values', 'stack', 'fault address', 'other event fields'],
                alignment='same-index first divergence; no insertion/deletion realignment')


def iter_event_archive(path):
    """Read version-1 indexed JSONL without loading the full trace into RAM."""
    with open(path, 'rb') as stream:
        index = 0
        while True:
            line = stream.readline(1024*1024+1)
            if not line:
                return
            if len(line) > 1024*1024 or not line.endswith(b'\n'):
                raise ValueError('Oversized or incomplete event archive record')
            record = json.loads(line, parse_constant=lambda s: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
            if not isinstance(record, dict):
                raise ValueError('Event archive record must be an object')
            if type(record.get('index')) is not int or record['index'] != index or not isinstance(record.get('event'), dict):
                raise ValueError('Invalid or noncontiguous event archive index')
            yield record['event']
            index += 1


def compare_event_streams(left, right, a, b, mode='exact-v1'):
    """Full-stream same-index diff with bounded memory and outcome comparison."""
    from itertools import zip_longest
    result = compare_reports({**left, 'trace': [], 'trace_start_index': 0},
                             {**right, 'trace': [], 'trace_start_index': 0}, mode)
    missing = object()
    counts = [0, 0]
    kinds = [Counter(), Counter()]
    prefix, first = 0, None
    for index, pair in enumerate(zip_longest(a, b, fillvalue=missing)):
        for side, event in enumerate(pair):
            if event is not missing:
                counts[side] += 1
                kinds[side][str(event.get('kind', 'unclassified'))] += 1
        if first is None:
            views = [event_view(event, meta, mode) if event is not missing else None
                     for event, meta in zip(pair, (left, right))]
            if views[0] == views[1]:
                prefix += 1
            else:
                first = dict(index=index, left=views[0], right=views[1])
    for metadata, count in zip((left, right), counts):
        if metadata.get('trace_total_events', count) != count:
            raise ValueError('Event archive count differs from report')
    result.update(compared_events_equal=first is None, common_prefix_events=prefix,
                  first_divergence=first, event_counts=dict(left=counts[0], right=counts[1]),
                  kind_counts=dict(left=dict(sorted(kinds[0].items())), right=dict(sorted(kinds[1].items()))),
                  complete_traces_compared=True)
    return result
