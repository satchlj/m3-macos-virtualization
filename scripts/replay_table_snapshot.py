#!/usr/bin/env python3
"""Replay bounded guest translation from hash-verified diagnostic table pages."""
import argparse
import hashlib
from pathlib import Path
import struct
from guest_pt import translate, UnmappedAddress, PAGE, MONITOR_TCR, MONITOR_MAIR
from run_manifest import atomic_json, file_identity
from trace_diff import load_report


def walk_snapshot(controls, pages, address):
    if controls['tcr'] != MONITOR_TCR or controls['mair'] != MONITOR_MAIR:
        raise ValueError('Snapshot profile is not the supported 47-bit monitor profile')
    path = []
    def read(table):
        data = pages[table]
        if len(data) != PAGE:
            raise ValueError('Truncated table page')
        level = len(path)+1
        index = (address >> (36,25,14)[level-1]) & 0x7ff
        path.append(dict(level=level, table=table, index=index,
                         descriptor=struct.unpack_from('<Q',data,index*8)[0]))
        return data
    result = dict(address=address, address_hex=hex(address), path=path)
    try:
        result.update(status='mapped', mapping=translate(address,controls['ttbr0'],controls['ttbr1'],read))
    except UnmappedAddress as error:
        result.update(status='unmapped', error=str(error))
    except KeyError as error:
        result.update(status='missing-table', missing_table=error.args[0],
                      error='Snapshot does not include the next table; mapping is unknown')
    except ValueError as error:
        result.update(status='invalid', error=str(error))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('report', type=Path)
    ap.add_argument('diagnostics', type=Path)
    ap.add_argument('tables', type=Path)
    ap.add_argument('--address', type=lambda x:int(x,0), action='append', help='Default: captured ELR and FAR')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    report, diagnostics = load_report(a.report), load_report(a.diagnostics)
    identity = file_identity(a.report)
    if report.get('run_id') != diagnostics.get('run_id') or any(
        identity[k] != diagnostics.get('source_report',{}).get(k) for k in ('sha256','size')):
        raise ValueError('Diagnostic source report identity mismatch')
    pages = {}
    for item in diagnostics['table_snapshot']['pages']:
        address = item['address']
        if address in pages or address % PAGE or not report['guest_base'] <= address < address+PAGE <= report['guest_base']+report['guest_size']:
            raise ValueError('Duplicate, misaligned or unowned table page')
        path = a.tables/Path(item['path']).name
        if path.name != f'{address:012x}.bin':
            raise ValueError('Snapshot filename does not match table address')
        data = path.read_bytes()
        if len(data) != PAGE or len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Table page identity mismatch')
        pages[address] = data
    addresses = a.address or [diagnostics['exception'][name] for name in ('ELR_EL12','FAR_EL12')]
    result = dict(scope='offline-partial-table-replay', run_id=report['run_id'],
        complete_address_space=False, source_report=identity,
        source_diagnostics=file_identity(a.diagnostics),
        walks=[walk_snapshot(report['monitor_mmu_controls'],pages,address) for address in addresses])
    atomic_json(a.output,result)
    for walk in result['walks']:
        print(walk['address_hex'],walk['status'])


if __name__ == '__main__':
    main()
