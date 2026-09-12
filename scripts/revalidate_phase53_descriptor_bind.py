#!/usr/bin/env python3
"""Revalidate descriptor-bind reports produced by the legacy opaque-FTE gate."""
import argparse
import hashlib
import json
from pathlib import Path


LEGACY_CHECK = 'fte_center_unchanged'


def revalidate(report_bytes):
    report = json.loads(report_bytes)
    bind = report['xnu_phase53_descriptor_bind']
    stages = bind['stages']
    pre_map = next(stage for stage in stages if stage['stage'] == 'pre-map-call')
    caller = next(stage for stage in stages if stage['stage'] == 'caller-return')

    false_checks = sorted(name for name, passed in caller['checks'].items()
                          if not passed)
    pre_records = pre_map['frame_table']['records']
    after_records = caller['frame_table_after']['records']
    pre_center = bytes.fromhex(pre_records[1]['hex'])
    after_center = bytes.fromhex(after_records[1]['hex'])
    changed_offsets = [index for index, (old, new) in enumerate(
                       zip(pre_center, after_center)) if old != new]

    checks = {
        'legacy_or_current_terminal': report['stop_reason'] in (
            'phase53-descriptor-bind-caller-return-gate-rejected',
            'phase53-descriptor-bind-reached'),
        'legacy_false_check_only': false_checks in ([], [LEGACY_CHECK]),
        'all_nonlegacy_checks': all(
            passed for name, passed in caller['checks'].items()
            if name != LEGACY_CHECK),
        'pre_map_complete': pre_map['complete'],
        'descriptor_exact': caller['descriptor'] ==
            pre_map['expected_descriptor'],
        'slot_exact': caller['slot_pa'] == pre_map['slot_pa'],
        'fte_records_sized': all(len(bytes.fromhex(record['hex'])) == 16
                                 for record in pre_records + after_records),
        'fte_generic_fields_stable': pre_center[:3] == after_center[:3],
        'fte_center_unlocked': int.from_bytes(after_center[:2], 'little') == 0,
        'fte_type_stable': pre_records[1]['type'] == after_records[1]['type'],
        'fte_neighbors_unchanged': (pre_records[0]['hex'] ==
                                    after_records[0]['hex'] and
                                    pre_records[2]['hex'] ==
                                    after_records[2]['hex']),
        'opaque_changes_only': all(index >= 3 for index in changed_offsets),
    }
    return {
        'schema_version': 1,
        'source_report_sha256': hashlib.sha256(report_bytes).hexdigest(),
        'run_id': report['run_id'],
        'source_stop_reason': report['stop_reason'],
        'descriptor': caller['descriptor'],
        'slot_pa': caller['slot_pa'],
        'fte_center_changed_offsets': changed_offsets,
        'checks': checks,
        'complete': all(checks.values()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = revalidate(args.report.read_bytes())
    encoded = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')
    raise SystemExit(0 if result['complete'] else 1)


if __name__ == '__main__':
    main()
