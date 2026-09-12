"""Bound a native guest using m1n1's existing timer-polled user interrupt.

All I/O stays on the probe thread. Only the outer hv_start receive wait polls;
Callback reads have a separate finite timeout and never get a kick. A callback
timeout poisons the transport: even cleanup code must not send another command.
This needs working EL2 timer delivery. If the kick gets no response, abandon the
connection after a grace period; callers MUST skip target cleanup in that case.
"""
import time


class GuestUnresponsive(TimeoutError):
    pass


class CallbackUnresponsive(GuestUnresponsive):
    pass


class FreeRunWatchdog:
    def __init__(self, iface, seconds, grace=15, clock=time.monotonic,
                 callback_read_timeout=3):
        if not 0 < seconds <= 86400 or not 0 < grace <= 300:
            raise ValueError('Invalid watchdog budget/grace')
        if not 0 < callback_read_timeout <= 300:
            raise ValueError('Invalid callback read timeout')
        self.iface = iface
        self.seconds = seconds
        self.grace = grace
        self.clock = clock
        self.in_callback = False
        self.kicked = False
        self.returned = False
        self.started = None
        self.callback_read_timeout = callback_read_timeout
        self.callback_error = None

    @property
    def expired(self):
        return self.started is not None and self.clock() >= self.started + self.seconds

    def run(self, launch):
        original_read = self.iface.dev.read
        original_write = self.iface.dev.write
        original_boot = self.iface.handle_boot
        self.started = self.clock()

        def callback(data):
            previous = self.in_callback
            self.in_callback = True
            try:
                result = original_boot(data)
                # A handler may catch TimeoutError. It still cannot resume the
                # outer reply parser after abandoning a partial proxy response.
                if self.callback_error is not None:
                    raise self.callback_error
                return result
            finally:
                self.in_callback = previous

        def read(size=1):
            if self.callback_error is not None:
                raise self.callback_error
            if self.in_callback:
                if size == 0:
                    return b''
                deadline = self.clock() + self.callback_read_timeout
                while True:
                    remaining = deadline - self.clock()
                    if remaining <= 0:
                        self.callback_error = CallbackUnresponsive(
                            'Proxy callback read timed out; connection abandoned without further I/O')
                        raise self.callback_error
                    timeout = self.iface.dev.timeout
                    self.iface.dev.timeout = min(0.25, remaining)
                    try:
                        data = original_read(size)
                    finally:
                        self.iface.dev.timeout = timeout
                    if data:
                        return data
            # hv_start's command write is already finished before any read runs.
            # A single kick matches HV.interrupt(); never interrupt a USB write.
            while True:
                now = self.clock()
                if now >= self.started + self.seconds + self.grace:
                    raise GuestUnresponsive('Guest did not return within watchdog budget + grace')
                if self.expired and not self.kicked:
                    original_write(b'!')
                    self.kicked = True
                timeout = self.iface.dev.timeout
                self.iface.dev.timeout = 0.25
                try:
                    data = original_read(size)
                finally:
                    self.iface.dev.timeout = timeout
                if data:
                    return data

        def write(data, *args, **kwargs):
            if self.callback_error is not None:
                raise self.callback_error
            return original_write(data, *args, **kwargs)

        self.iface.dev.read = read
        self.iface.dev.write = write
        self.iface.handle_boot = callback
        try:
            result = launch()
            if self.callback_error is not None:
                raise self.callback_error
            self.returned = True
            return result
        finally:
            self.iface.dev.read = original_read
            self.iface.dev.write = original_write
            self.iface.handle_boot = original_boot

    def status(self):
        return dict(budget_seconds=self.seconds, grace_seconds=self.grace,
                    mechanism='EL2 timer-polled user interrupt',
                    kicked=self.kicked, guest_returned=self.returned,
                    callback_read_timeout_seconds=self.callback_read_timeout,
                    callback_read_timed_out=self.callback_error is not None)
