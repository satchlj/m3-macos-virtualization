"""Drain bounded native software-step records; never emulate their instructions."""
import struct
from run_manifest import append_event, trace_count
RECORD = struct.Struct('<39Q')


class StepBatch:
    def __init__(self, proxy, iface, address, capacity):
        if not 1 <= capacity <= 256 or address % 8:
            raise ValueError('Invalid native trace buffer')
        self.proxy, self.iface, self.address, self.capacity = proxy, iface, address, capacity
        self.armed = False
        self.quota = capacity

    def drain(self, report):
        if not self.armed:
            return
        count = self.proxy.hv_vel2_trace_count()
        if not 0 <= count <= self.quota:
            raise ValueError('Native trace count exceeds armed quota')
        data = self.iface.readmem(self.address, count*RECORD.size) if count else b''
        if len(data) != count*RECORD.size:
            raise ValueError('Truncated native trace batch')
        events = []
        for values in RECORD.iter_unpack(data):
            pc, esr, far, spsr = values[:4]
            if esr >> 26 != 0x32 or spsr & 15 not in (4, 5):
                raise ValueError('Unexpected event in native step batch')
            events.append(dict(reason=2, code=0, pc=pc, esr=esr, far=far,
                spsr=spsr, regs=list(values[4:36]), sp=list(values[36:39]), kind='instruction-step'))
        # Acknowledge only after the complete batch has been read and validated.
        self.proxy.hv_vel2_trace_config(0, 0)
        self.armed = False
        for event in events:
            append_event(report, event)
        report['native_batched_events'] = report.get('native_batched_events', 0)+count

    def arm(self, report, budget):
        quota = min(self.capacity, max(0, budget-trace_count(report)))
        if quota:
            self.proxy.hv_vel2_trace_config(self.address, quota)
            self.quota = quota
            self.armed = True

    def disable(self):
        self.proxy.hv_vel2_trace_config(0, 0)
        self.armed = False
