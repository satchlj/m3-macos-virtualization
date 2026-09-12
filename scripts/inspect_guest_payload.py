#!/usr/bin/env python3
"""Inspect Mach-O load commands only; no disassembly, imports of m1n1 or device I/O."""
import argparse
import json
import struct
from pathlib import Path


def inspect(data):
    if len(data) < 32:
        raise ValueError('Truncated Mach-O header')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', data)
    if magic != 0xfeedfacf or cpu != 0x100000c:
        raise ValueError('Expected little-endian 64-bit ARM Mach-O')
    if kind not in (2, 12):
        raise ValueError('Expected executable or fileset')
    end = 32 + size
    if end > len(data) or count > size // 8:
        raise ValueError('Invalid load-command extent')
    pos = 32
    segments = []
    entries = []
    for _ in range(count):
        if pos + 8 > end:
            raise ValueError('Truncated load command')
        cmd, length = struct.unpack_from('<II', data, pos)
        if length < 8 or length % 8 or pos + length > end:
            raise ValueError('Invalid load-command size')
        if cmd == 0x19:
            if length < 72:
                raise ValueError('Truncated segment command')
            name = data[pos + 8:pos + 24].split(b'\0', 1)[0].decode('ascii')
            va, extent, offset, file_size = struct.unpack_from('<4Q', data, pos + 24)
            nsects = struct.unpack_from('<I', data, pos + 64)[0]
            if length != 72 + nsects * 80 or offset + file_size > len(data):
                raise ValueError('Invalid segment extent')
            if va + extent > 1 << 64:
                raise ValueError('Segment address overflow')
            segments.append((name, va, extent))
        elif cmd == 5:
            cursor = pos + 8
            while cursor < pos + length:
                if cursor + 8 > pos + length:
                    raise ValueError('Truncated thread state')
                flavor, words = struct.unpack_from('<II', data, cursor)
                state_end = cursor + 8 + words * 4
                if state_end > pos + length:
                    raise ValueError('Invalid thread state extent')
                if flavor == 6:
                    if words != 68:
                        raise ValueError('Invalid ARM_THREAD_STATE64 size')
                    entries.append(struct.unpack_from('<Q', data, cursor + 8 + 32 * 8)[0])
                cursor = state_end
        pos += length
    if pos != end:
        raise ValueError('Load-command count does not consume declared extent')
    if len(entries) != 1:
        raise ValueError('Expected exactly one ARM64 UNIXTHREAD entry')
    owners = [name for name, va, extent in segments if va <= entries[0] < va + extent]
    if len(owners) != 1:
        raise ValueError('Entry is outside segments or has ambiguous segment ownership')
    names = [name for name, _, _ in segments]
    monitor_markers = owners[0] == '__TEXT_BOOT_EXEC' or '__DATA_SPTM' in names
    return {
        'scope': 'offline-mach-o-entry-metadata',
        'guest_boot_verified': False,
        'filetype': 'fileset' if kind == 12 else 'executable',
        'entry_segment': owners[0],
        'sptm_data_segment_present': '__DATA_SPTM' in names,
        'direct_loader_contract': 'blocked-pending-monitor-contract' if monitor_markers else 'unknown',
        'detail': ('Monitor entry markers require investigation before the current one-argument '
                   'guest entry path. Metadata alone does not establish shipping ABI or active monitors.'
                   if monitor_markers else 'No recognized monitor marker; this does not establish boot readiness.'),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('payload', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.payload.read_bytes())
    except (OSError, ValueError, UnicodeError, struct.error):
        print(json.dumps({'error': 'Invalid or unreadable Mach-O payload', 'guest_boot_verified': False}))
        return 2
    print(json.dumps(result, indent=2))
    return 2 if result['direct_loader_contract'].startswith('blocked') else 0


if __name__ == '__main__':
    raise SystemExit(main())
