#!/usr/bin/env python3
"""Read bounded printable guest data after a completed probe; never resume a guest.

Use only the latest attempt on the unchanged RAM-loaded image, with no other
owner of the target. A report alone cannot prove its guest RAM is still current.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys
from guest_pt import translate, PAGE
from run_manifest import atomic_json, file_identity, utc
from trace_diff import load_report
from vel2_smoke import verify_image

MAX_VA_READ = 4096
PANIC_CARVEOUT_ID = 'region-id-98'
PANIC_CARVEOUT_BASE = 0x103e6c28000
PANIC_CARVEOUT_SIZE = 0x188000
PANIC_HEADER_SIZE = 64
APPLE_PHYSICAL_TIMER_PC = 0xfffffe002bf923b4
APPLE_PHYSICAL_TIMER_ESR = 0x62387d1a
APPLE_PHYSICAL_TIMER_VALUE = 2
APPLE_PHYSICAL_TIMER_EL02 = (3, 4, 15, 4, 3)
SOCD_TRACE_BASE = 0x2ede69014
SOCD_TRACE_SIZE = 0x39c
SOCD_TRACE_FAR = 0xfffffe003a61d014
SOCD_TRACE_PC = 0xfffffe002b72118c
SOCD_TRACE_ESR = 0x93890046
SOCD_TRACE_VALUE = 2


def verify_apple_physical_timer_stop(report):
    """Bind a candidate-bank read to the exact retained attempt-65 stop."""
    if report.get('stop_reason') != 'xnu-native-exception':
        raise ValueError('Source did not stop at an XNU native exception')
    try:
        event = next(e for e in reversed(report['trace'])
                     if e.get('kind') == 'xnu-native-exception')
        value = int(event['regs'][8])
    except (KeyError, IndexError, StopIteration, TypeError, ValueError):
        raise ValueError('Source lacks the retained Apple timer exception context')
    if ((event.get('pc'), event.get('esr'), value) !=
            (APPLE_PHYSICAL_TIMER_PC, APPLE_PHYSICAL_TIMER_ESR,
             APPLE_PHYSICAL_TIMER_VALUE)):
        raise ValueError('Source Apple timer exception tuple mismatch')
    return dict(pc=event['pc'], esr=event['esr'], requested_value=value,
                candidate_register='S3_4_C15_C4_3',
                candidate_encoding=list(APPLE_PHYSICAL_TIMER_EL02),
                routing_established=False, bit_semantics_established=False,
                physical_s3_1_bank_touched=False)


def verify_panic_carveout(report, manifest, archived_path, archived_bytes,
                          live_bytes, load_adt):
    """Bind the one permitted physical read to attempt-62's live DT carveout."""
    if manifest.get('run_id') != report.get('run_id') or manifest.get('status') != 'finished':
        raise ValueError('Manifest does not identify the completed source run')
    captured = manifest.get('captured_inputs', {}).get('host-device-tree.adt')
    if not captured or Path(captured.get('path', '')).name != 'host-device-tree.adt':
        raise ValueError('Manifest lacks the archived host device tree')
    identity = file_identity(archived_path)
    if any(identity.get(key) != captured.get(key) for key in ('sha256', 'size')):
        raise ValueError('Archived device tree identity mismatch')
    digest = hashlib.sha256(live_bytes).hexdigest()
    if (archived_bytes != live_bytes or digest != report.get('device_tree_sha256')
            or digest != captured.get('sha256')):
        raise ValueError('Live device tree does not match the archived source input')
    values = []
    for label, blob in (('archived', archived_bytes), ('live', live_bytes)):
        tree = load_adt(blob)
        region = tuple(map(int, tree['chosen']['carveout-memory-map']._properties[
            PANIC_CARVEOUT_ID]))
        if region != (PANIC_CARVEOUT_BASE, PANIC_CARVEOUT_SIZE):
            raise ValueError(label + ' panic carveout tuple mismatch')
        values.append(region)
    return dict(region_id=PANIC_CARVEOUT_ID, base=values[0][0], size=values[0][1],
                header_size=PANIC_HEADER_SIZE, archived_adt=identity,
                live_adt_sha256=digest)


def read_panic_carveout_header(readmem, carveout):
    if ((carveout.get('base'), carveout.get('size'), carveout.get('header_size')) !=
            (PANIC_CARVEOUT_BASE, PANIC_CARVEOUT_SIZE, PANIC_HEADER_SIZE)):
        raise ValueError('Unverified panic carveout read request')
    data = readmem(PANIC_CARVEOUT_BASE, PANIC_HEADER_SIZE)
    if len(data) != PANIC_HEADER_SIZE:
        raise ValueError('Truncated panic carveout header read')
    return data


def verify_socd_trace_buffer(report, manifest, archived_path, archived_bytes,
                             live_bytes, load_adt):
    """Bind a 924-byte read to the exact attempt-66 fault and live ADT node."""
    if manifest.get('run_id') != report.get('run_id') or manifest.get('status') != 'finished':
        raise ValueError('Manifest does not identify the completed source run')
    captured = manifest.get('captured_inputs', {}).get('host-device-tree.adt')
    if not captured or Path(captured.get('path', '')).name != 'host-device-tree.adt':
        raise ValueError('Manifest lacks the archived host device tree')
    identity = file_identity(archived_path)
    if any(identity.get(key) != captured.get(key) for key in ('sha256', 'size')):
        raise ValueError('Archived device tree identity mismatch')
    digest = hashlib.sha256(live_bytes).hexdigest()
    if (archived_bytes != live_bytes or digest != report.get('device_tree_sha256')
            or digest != captured.get('sha256')):
        raise ValueError('Live device tree does not match the archived source input')
    try:
        event = next(e for e in reversed(report['trace'])
                     if e.get('kind') == 'xnu-native-exception')
        value = int(event['regs'][9]) & 0xffffffff
        far = int(event['regs'][11])
    except (KeyError, IndexError, StopIteration, TypeError, ValueError):
        raise ValueError('Source lacks the retained SOCd exception context')
    if ((event.get('pc'), event.get('esr'), event.get('far'), far, value) !=
            (SOCD_TRACE_PC, SOCD_TRACE_ESR, SOCD_TRACE_FAR,
             SOCD_TRACE_FAR, SOCD_TRACE_VALUE)):
        raise ValueError('Source SOCd exception tuple mismatch')
    for label, blob in (('archived', archived_bytes), ('live', live_bytes)):
        node = load_adt(blob)['socd-trace-ram']
        region = tuple(map(int, node.get_reg(0)))
        if region != (SOCD_TRACE_BASE, SOCD_TRACE_SIZE):
            raise ValueError(label + ' SOCd trace tuple mismatch')
        if node._properties.get('device_type') != 'socd-trace-ram':
            raise ValueError(label + ' SOCd trace device type mismatch')
    return dict(base=SOCD_TRACE_BASE, size=SOCD_TRACE_SIZE,
                device_tree_path='/socd-trace-ram', device_type='socd-trace-ram',
                fault_pc=SOCD_TRACE_PC, fault_esr=SOCD_TRACE_ESR,
                fault_va=SOCD_TRACE_FAR, fault_value=value,
                archived_adt=identity, live_adt_sha256=digest)


def read_socd_trace_buffer(readmem, contract):
    if ((contract.get('base'), contract.get('size')) !=
            (SOCD_TRACE_BASE, SOCD_TRACE_SIZE)):
        raise ValueError('Unverified SOCd trace read request')
    data = readmem(SOCD_TRACE_BASE, SOCD_TRACE_SIZE)
    if len(data) != SOCD_TRACE_SIZE:
        raise ValueError('Truncated SOCd trace buffer read')
    return data


def parse_va_read(spec):
    address, separator, length = spec.partition(':')
    if not separator:
        raise ValueError('Expected VA:LENGTH')
    try:
        address, length = int(address, 0), int(length, 0)
    except ValueError:
        raise ValueError('Expected integer VA:LENGTH')
    if not 0 <= address < 1 << 64 or not 1 <= length <= MAX_VA_READ or address + length > 1 << 64:
        raise ValueError('VA read must be uint64 and 1..4096 bytes')
    return address, length


def read_guest_va(report, controls, readmem, va, length, table_pages=None):
    """Translate and read a small guest VA span entirely from owned guest RAM."""
    if not 0 <= va < 1 << 64 or not 1 <= length <= MAX_VA_READ or va + length > 1 << 64:
        raise ValueError('Invalid bounded guest VA read')
    base, size = report['guest_base'], report['guest_size']
    def owned(address, count):
        if not base <= address < address + count <= base + size:
            raise ValueError('Read outside owned guest RAM')
        data = readmem(address, count)
        if len(data) != count:
            raise ValueError('Truncated guest read')
        return data
    def read_table(address):
        if address % PAGE:
            raise ValueError('Misaligned guest table page')
        data = owned(address, PAGE)
        if table_pages is not None:
            table_pages[address] = data
        return data
    data, mappings = bytearray(), []
    cursor = va
    while len(data) < length:
        mapping = translate(cursor, controls['ttbr0'], controls['ttbr1'], read_table)
        if not mapping['access_flag']:
            raise ValueError('Guest mapping access flag is clear')
        count = min(length - len(data), PAGE - (cursor % PAGE), PAGE - (mapping['pa'] % PAGE))
        data.extend(owned(mapping['pa'], count))
        mappings.append(dict(va=cursor, pa=mapping['pa'], bytes=count,
                             level=mapping['level'], descriptor=mapping['descriptor']))
        cursor += count
    return bytes(data), mappings


def printable_pointers(report, readmem, table_pages=None):
    base, size = report['guest_base'], report['guest_size']
    def bounded(address, length):
        if not base <= address or length <= 0 or address+length > base+size:
            raise ValueError('Read outside owned guest RAM')
        data = readmem(address, length)
        if len(data) != length:
            raise ValueError('Truncated guest read')
        return data
    controls = report['monitor_mmu_controls']
    def read_table(address):
        data = bounded(address, PAGE)
        if table_pages is not None:
            table_pages[address] = data
        return data
    event = next(e for e in reversed(report['trace']) if 'regs' in e)
    strings = []
    for index, va in enumerate(event['regs'][:30]):
        try:
            mapping = translate(va, controls['ttbr0'], controls['ttbr1'], read_table)
            pa = mapping['pa']
            length = min(256, PAGE-pa % PAGE, base+size-pa)
            data = bounded(pa, length).split(b'\0', 1)[0]
            if len(data) >= 8 and all(c in (9, 10, 13) or 32 <= c < 127 for c in data):
                strings.append(dict(register=index, va=va, text=data.decode('ascii'),
                                    possibly_truncated=len(data) == length))
        except ValueError:
            continue
    return strings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('report', type=Path)
    ap.add_argument('--checkout', type=Path, default=os.environ.get('VEL2_CHECKOUT'))
    ap.add_argument('--device', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--table-snapshot', type=Path, help='New directory for table pages visited by register-pointer walks and requested VA reads; not a full address-space dump')
    ap.add_argument('--read-va', action='append', default=[], metavar='VA:LENGTH', help='Read at most 4096 bytes through the live final guest EL12 translation controls; repeatable')
    ap.add_argument('--read-panic-carveout-header', action='store_true', help='Read exactly 64 bytes from the attempt-62 panic carveout after live and archived DT identity checks; requires --manifest')
    ap.add_argument('--manifest', type=Path, help='Completed source-run manifest binding the requested carveout or timer diagnostic')
    ap.add_argument('--read-apple-physical-timer-alias', action='store_true',
                    help='Read candidate S3_4_C15_C4_3 twice after the exact retained attempt-65 trap; never writes or resumes')
    ap.add_argument('--read-socd-trace-buffer', action='store_true',
                    help='Read exactly the 924-byte /socd-trace-ram region after exact attempt-66 and live/archived DT checks')
    a = ap.parse_args()
    if a.checkout is None:
        ap.error('A checkout is required')
    identity_bound_read = (a.read_panic_carveout_header or
                           a.read_apple_physical_timer_alias or
                           a.read_socd_trace_buffer)
    if identity_bound_read != (a.manifest is not None):
        ap.error('identity-bound physical diagnostics require --manifest')
    report = load_report(a.report)
    if not report.get('stop_reason') or report.get('proxy_alive_after_exit') is not True:
        ap.error('Source must be a completed probe with a responsive proxy')
    try:
        read_requests = [(spec, *parse_va_read(spec)) for spec in a.read_va]
    except ValueError as error:
        ap.error(str(error))
    read_paths = [a.output.with_name(a.output.stem + '-va-%016x.bin' % va)
                  for _, va, _ in read_requests]
    panic_path = a.output.with_name(a.output.stem + '-panic-carveout-header.bin')
    socd_path = a.output.with_name(a.output.stem + '-socd-trace-buffer.bin')
    if a.read_panic_carveout_header:
        read_paths.append(panic_path)
    if a.read_socd_trace_buffer:
        read_paths.append(socd_path)
    if len(set(read_paths)) != len(read_paths) or any(path.exists() for path in read_paths):
        ap.error('VA read outputs must be unique and not already exist')
    sys.path.insert(0, str(a.checkout.resolve()/'proxyclient'))
    from m1n1.proxy import UartInterface, M1N1Proxy
    from m1n1.proxyutils import ProxyUtils
    from m1n1.adt import load_adt
    from m1n1 import sysreg
    result = dict(scope='bounded-read-only-guest-diagnostics', checked_at=utc(),
                  source_report=file_identity(a.report), run_id=report.get('run_id'),
                  device=a.device, guest_resumed=False)
    iface = None
    try:
        iface = UartInterface(a.device)
        iface.nop()
        proxy = M1N1Proxy(iface)
        proxy.nop()
        result['image_sections'] = verify_image(iface, proxy.get_base(), a.checkout/'build/m1n1-raw.elf')
        utils = ProxyUtils(proxy)
        manifest = None
        if identity_bound_read:
            manifest = load_report(a.manifest)
            if (manifest.get('run_id') != report.get('run_id') or
                    manifest.get('status') != 'finished'):
                raise ValueError('Manifest does not identify the completed source run')
            runtime = file_identity(a.checkout/'build/m1n1-raw.elf')
            expected_runtime = manifest.get('expected_runtime', {})
            if any(runtime.get(key) != expected_runtime.get(key)
                   for key in ('sha256', 'size')):
                raise ValueError('Live runtime image identity differs from source manifest')
            result['runtime_identity'] = runtime
        if a.read_apple_physical_timer_alias:
            contract = verify_apple_physical_timer_stop(report)
            first = int(utils.mrs(APPLE_PHYSICAL_TIMER_EL02))
            second = int(utils.mrs(APPLE_PHYSICAL_TIMER_EL02))
            result['apple_physical_timer_alias'] = dict(
                **contract, reads=[first, second], read_only=True,
                guest_resumed=False, full_raw_values=True)
        if a.read_panic_carveout_header:
            captured = manifest.get('captured_inputs', {}).get('host-device-tree.adt', {})
            archived_path = Path(captured.get('path', ''))
            archived_bytes = archived_path.read_bytes()
            carveout = verify_panic_carveout(
                report, manifest, archived_path, archived_bytes, utils.get_adt(), load_adt)
            data = read_panic_carveout_header(iface.readmem, carveout)
            panic_path.write_bytes(data)
            result['panic_carveout_header'] = dict(**carveout, output=str(panic_path),
                sha256=hashlib.sha256(data).hexdigest(), read_only=True)
        if a.read_socd_trace_buffer:
            captured = manifest.get('captured_inputs', {}).get('host-device-tree.adt', {})
            archived_path = Path(captured.get('path', ''))
            archived_bytes = archived_path.read_bytes()
            contract = verify_socd_trace_buffer(
                report, manifest, archived_path, archived_bytes, utils.get_adt(), load_adt)
            data = read_socd_trace_buffer(iface.readmem, contract)
            socd_path.write_bytes(data)
            result['socd_trace_buffer'] = dict(**contract, output=str(socd_path),
                sha256=hashlib.sha256(data).hexdigest(), read_only=True,
                adjacent_page_bytes_read=0)
        result['exception'] = {name: utils.mrs(getattr(sysreg, name)) for name in
            ('ESR_EL12', 'ELR_EL12', 'FAR_EL12', 'SPSR_EL12', 'VBAR_EL12', 'SCTLR_EL12')}
        pages = {} if a.table_snapshot is not None else None
        result['strings'] = printable_pointers(report, iface.readmem, pages)
        if read_requests:
            controls = {name: int(utils.mrs(getattr(sysreg, name.upper() + '_EL12')))
                        for name in ('ttbr0', 'ttbr1', 'tcr', 'mair')}
            result['read_va_controls'] = dict(source='live final guest EL12 aliases', **controls)
            result['va_reads'] = []
            for spec, va, length in read_requests:
                data, mappings = read_guest_va(report, controls, iface.readmem, va, length, pages)
                path = a.output.with_name(a.output.stem + '-va-%016x.bin' % va)
                path.write_bytes(data)
                result['va_reads'].append(dict(va=va, length=length, mappings=mappings,
                    output=str(path), sha256=hashlib.sha256(data).hexdigest()))
        if pages is not None:
            a.table_snapshot.mkdir(parents=True, exist_ok=False)
            result['table_snapshot'] = dict(scope='tables visited by at most 30 register-pointer walks and explicit bounded VA reads',
                complete_address_space=False, pages=[])
            for address, data in sorted(pages.items()):
                path = a.table_snapshot/f'{address:012x}.bin'
                path.write_bytes(data)
                result['table_snapshot']['pages'].append(dict(address=address, **file_identity(path)))
        proxy.nop()
        result['proxy_alive'] = True
    except BaseException as error:
        result['error'] = str(error)
        raise
    finally:
        if iface is not None:
            iface.dev.close()
        atomic_json(a.output, result)


if __name__ == '__main__':
    main()
