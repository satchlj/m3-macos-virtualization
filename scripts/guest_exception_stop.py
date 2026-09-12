"""Pure, incremental stop decision for recorded guest vector PCs.

This observes trace records, not ESR: an old guest ESR alone is never a hit.
No target reads, event mutation, instruction emulation, or trace filtering occur.
"""
from copy import deepcopy


class GuestExceptionStop:
    """Scan every newly recorded event once against the current sampled VBAR.

    Feed each drained batch plus its host callback before resuming the guest.
    ``start_index`` is the global zero-based index of events[0]. A rolling
    window may overlap a previous call, but must not discard unseen events.
    """

    def __init__(self, batch_capacity=0):
        if not isinstance(batch_capacity, int) or not 0 <= batch_capacity <= 256:
            raise ValueError('batch_capacity must be between 0 and 256')
        self.batch_capacity = batch_capacity
        self.next_index = 0
        self.hit = None

    def observe(self, events, *, start_index, vbar):
        """Return a latched hit dictionary or None; vbar=0 means unconfigured.

        The entry-guard record is synthetic and excluded. PC membership is
        evidence of a vector-range visit, not proof of its architectural cause.
        VBAR is sampled at this host stop, not historically reconstructed.
        """
        if not isinstance(start_index, int) or start_index < 0:
            raise ValueError('start_index must be a nonnegative integer')
        if not isinstance(vbar, int) or not 0 <= vbar <= (1 << 64)-2048 or vbar % 2048:
            raise ValueError('VBAR must be an aligned 64-bit vector base')
        end = start_index + len(events)
        if start_index > self.next_index:
            raise ValueError('Trace window discarded unseen events')
        if end < self.next_index:
            raise ValueError('Trace observations moved backwards')
        unseen = end - self.next_index
        if unseen > self.batch_capacity + 1:
            raise ValueError('Observation exceeds one native batch plus callback')
        if self.hit is None:
            for index in range(self.next_index, end):
                event = events[index-start_index]
                pc = event.get('pc')
                if (vbar and isinstance(pc, int) and vbar <= pc < vbar+2048
                        and event.get('kind') != 'entry-guard'):
                    self.hit = dict(
                        kind='guest-vector-range-entry', trace_index=index,
                        event=deepcopy(event), sampled_vbar=vbar,
                        vbar_sampling='current-host-stop',
                        observed_through_index=end-1,
                        recorded_events_after_hit=end-1-index,
                        maximum_recorded_overshoot=self.batch_capacity,
                        cause_status='not-yet-sampled')
                    break
        self.next_index = end
        return deepcopy(self.hit)

    def snapshot_cause(self, registers):
        """Attach registers read while stopped, without assigning stale cause.

        Caller should supply ESR_EL12, ELR_EL12, FAR_EL12, SPSR_EL12 and
        VBAR_EL12. These are stop-time observations; a later exception within
        the batch may have replaced the first vector visit's cause registers.
        """
        if self.hit is None:
            raise ValueError('No vector entry has been observed')
        self.hit['stop_guest_exception_registers'] = deepcopy(registers)
        self.hit['cause_status'] = 'sampled-at-stop-not-proven-first-entry'
        return deepcopy(self.hit)
