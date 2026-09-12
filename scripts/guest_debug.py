"""Guest-only debug state for the bounded SPTM probe, with no proxy access.

This is an explicit disabled-debug profile, not architectural reset emulation.
Only TDCC may be set: DCC accesses still stop in the probe; guest debug
enables remain unsupported and never change physical single-step controls.
See docs/offline-debug-model.md for the public-source basis and limitations.
"""

MDSCR_EL1 = (2, 0, 0, 2, 2)
TDCC = 1 << 12
OSLAR_EL1 = (2, 0, 1, 0, 4)


class UnsupportedGuestDebug(ValueError):
    """A recognized guest debug access exceeds the supported profile."""


class GuestDebugState:
    def __init__(self):
        self.mdscr = 0
        self.oslock = None  # No guest unlock observed yet; not a host lock read.

    def snapshot(self):
        return {'profile': 'disabled-debug', 'mdscr': self.mdscr, 'oslock': self.oslock}

    def access(self, reg, read, value):
        """Return event metadata for an accepted access, or None if unknown.

        No context, host registers, or transport are accessible here. Validate
        writes before changing state, so rejected requests are transactional.
        """
        if reg == MDSCR_EL1:
            if not read and value not in (0, TDCC):
                raise UnsupportedGuestDebug('Only zero or TDCC-only guest MDSCR_EL1 writes are supported')
            if not read:
                self.mdscr = value
            return {'kind': 'emulated-guest-mdscr', 'value': self.mdscr}
        if reg == OSLAR_EL1:
            if read or value != 0:
                raise UnsupportedGuestDebug('Only guest OSLAR_EL1 zero writes are supported')
            self.oslock = 0
            return {'kind': 'emulated-oslock-unlock', 'value': 0}
        return None
