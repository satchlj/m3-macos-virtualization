# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Firmware adapter interfaces and teardown auditing."""
from sptm_layout import PAGE

class PpermWindowLimit(Exception):
    pass


class TpidrGl2FastShadow:
    """Strict host boundary for the opt-in firmware TPIDR_GL2 HVC fast path."""
    ENABLE = 'hv_vel2_tpidr_gl2_shadow_enable'
    STATUS = 'hv_vel2_tpidr_gl2_shadow_status'
    DISABLE = 'hv_vel2_tpidr_gl2_shadow_disable'
    STATUS_FIELDS = ('enabled', 'tag_base', 'shadow', 'reads',
                     'writes', 'forwarded')

    def __init__(self, proxy):
        self.proxy = proxy
        missing = [name for name in (self.ENABLE, self.STATUS, self.DISABLE)
                   if not callable(getattr(proxy, name, None))]
        if missing:
            raise RuntimeError('TPIDR_GL2 fast-shadow proxy API unavailable: ' +
                               ', '.join(missing))

    @staticmethod
    def _validate_tag(tag_base):
        if (type(tag_base) is not int or not 0 <= tag_base <= 0xffff or
                tag_base & 0xc03f != 0x8000):
            raise RuntimeError('Invalid TPIDR_GL2 fast-shadow HVC tag base: ' +
                               repr(tag_base))

    def status(self):
        status = getattr(self.proxy, self.STATUS)()
        if not isinstance(status, dict):
            raise RuntimeError('TPIDR_GL2 fast-shadow status is not a dictionary')
        missing = [name for name in self.STATUS_FIELDS if name not in status]
        if missing:
            raise RuntimeError('TPIDR_GL2 fast-shadow status missing: ' +
                               ', '.join(missing))
        if type(status['enabled']) is not bool:
            raise RuntimeError('TPIDR_GL2 fast-shadow enabled status is not Boolean')
        for name in self.STATUS_FIELDS[1:]:
            value = status[name]
            if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
                raise RuntimeError('TPIDR_GL2 fast-shadow status field is not u64: ' + name)
        if status['enabled'] or status['tag_base']:
            self._validate_tag(status['tag_base'])
        return {name: status[name] for name in self.STATUS_FIELDS}

    @staticmethod
    def _check_result(operation, result):
        # Existing m1n1 proxy wrappers raise on firmware errors and return None;
        # accepting an explicit zero also keeps the boundary usable with raw wrappers.
        if result not in (None, 0):
            raise RuntimeError('TPIDR_GL2 fast-shadow %s failed: %r' %
                               (operation, result))

    def prepare(self):
        """Prove the accelerator is disabled before any guest can run."""
        before = self.status()
        if before['enabled']:
            self._check_result('preflight disable',
                               getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['enabled']:
            raise RuntimeError('TPIDR_GL2 fast shadow remained enabled at preflight')
        return dict(before=before, after=after,
                    stale_state_cleared=before['enabled'])

    def enable(self, tag_base, initial_value):
        self._validate_tag(tag_base)
        if type(initial_value) is not int or not 0 <= initial_value <= (1 << 64) - 1:
            raise RuntimeError('Invalid TPIDR_GL2 fast-shadow initial value')
        try:
            self._check_result('enable', getattr(self.proxy, self.ENABLE)(
                tag_base, initial_value))
            status = self.status()
            if (not status['enabled'] or status['tag_base'] != tag_base or
                    status['shadow'] != initial_value or
                    any(status[name] for name in
                        ('reads', 'writes', 'forwarded'))):
                raise RuntimeError('TPIDR_GL2 fast-shadow enable readback mismatch')
            return status
        except Exception as enable_error:
            # An ambiguous transport failure may have occurred after firmware changed
            # state. Always attempt the independent disable operation before returning
            # control to a callback that will exit the guest.
            try:
                self._check_result('enable-failure disable',
                                   getattr(self.proxy, self.DISABLE)())
                after = self.status()
                if after['enabled']:
                    raise RuntimeError('still enabled')
            except Exception as disable_error:
                raise RuntimeError('%s; fail-closed disable also failed: %s' %
                                   (enable_error, disable_error)) from enable_error
            raise

    def disable(self):
        self._check_result('disable', getattr(self.proxy, self.DISABLE)())
        status = self.status()
        if status['enabled']:
            raise RuntimeError('TPIDR_GL2 fast shadow remained enabled at teardown')
        return status


class Gl1FastRedirect:
    """Fail-closed host boundary for the exact live GL12 redirect fast path."""
    ENABLE = 'hv_vel2_gl1_fast_enable'
    STATUS = 'hv_vel2_gl1_fast_status'
    DISABLE = 'hv_vel2_gl1_fast_disable'
    TAG_NAMES = ('SPSR_GL1', 'ASPSR_GL1', 'ESR_GL1', 'ELR_GL1')
    STATUS_FIELDS = (
        'enabled', 'pc_base', 'spsr_tag', 'aspsr_tag', 'esr_tag', 'elr_tag',
        'handled', 'forwarded', 'write_spsr', 'write_elr', 'read_aspsr',
        'write_aspsr', 'read_esr', 'read_spsr', 'read_elr')

    def __init__(self, proxy):
        self.proxy = proxy
        missing = [name for name in (self.ENABLE, self.STATUS, self.DISABLE)
                   if not callable(getattr(proxy, name, None))]
        if missing:
            raise RuntimeError('GL1 fast-redirect proxy API unavailable: ' +
                               ', '.join(missing))

    @staticmethod
    def _validate_tag(tag):
        if (type(tag) is not int or not 0 <= tag <= 0xffff or
                tag & 0xc03f != 0x8000):
            raise RuntimeError('Invalid GL1 fast-redirect HVC tag: ' + repr(tag))

    def status(self):
        status = getattr(self.proxy, self.STATUS)()
        if not isinstance(status, dict):
            raise RuntimeError('GL1 fast-redirect status is not a dictionary')
        missing = [name for name in self.STATUS_FIELDS if name not in status]
        if missing:
            raise RuntimeError('GL1 fast-redirect status missing: ' +
                               ', '.join(missing))
        if type(status['enabled']) is not bool:
            raise RuntimeError('GL1 fast-redirect enabled status is not Boolean')
        for name in self.STATUS_FIELDS[1:]:
            value = status[name]
            if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
                raise RuntimeError('GL1 fast-redirect status field is not u64: ' + name)
        if status['enabled']:
            if not status['pc_base'] or status['pc_base'] & (PAGE - 1):
                raise RuntimeError('Invalid GL1 fast-redirect PC base readback')
            for name in ('spsr_tag', 'aspsr_tag', 'esr_tag', 'elr_tag'):
                self._validate_tag(status[name])
        return {name: status[name] for name in self.STATUS_FIELDS}

    @staticmethod
    def _check_result(operation, result):
        if result not in (None, 0):
            raise RuntimeError('GL1 fast-redirect %s failed: %r' %
                               (operation, result))

    def prepare(self):
        before = self.status()
        if before['enabled']:
            self._check_result('preflight disable',
                               getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['enabled']:
            raise RuntimeError('GL1 fast redirect remained enabled at preflight')
        return dict(before=before, after=after,
                    stale_state_cleared=before['enabled'])

    def enable(self, pc_base, tags):
        if type(pc_base) is not int or not pc_base or pc_base & (PAGE - 1):
            raise RuntimeError('Invalid GL1 fast-redirect PC base')
        if (not isinstance(tags, dict) or
                any(name not in tags for name in self.TAG_NAMES)):
            raise RuntimeError('GL1 fast-redirect tags are incomplete')
        for name in self.TAG_NAMES:
            self._validate_tag(tags[name])
        if len({tags[name] for name in self.TAG_NAMES}) != len(self.TAG_NAMES):
            raise RuntimeError('GL1 fast-redirect tags are not distinct')
        expected_tags = dict(zip(
            ('spsr_tag', 'aspsr_tag', 'esr_tag', 'elr_tag'),
            (tags[name] for name in self.TAG_NAMES)))
        try:
            self._check_result('enable', getattr(self.proxy, self.ENABLE)(
                pc_base, tags))
            status = self.status()
            counters = self.STATUS_FIELDS[6:]
            if (not status['enabled'] or status['pc_base'] != pc_base or
                    any(status[name] != value
                        for name, value in expected_tags.items()) or
                    any(status[name] for name in counters)):
                raise RuntimeError('GL1 fast-redirect enable readback mismatch')
            return status
        except Exception as enable_error:
            try:
                self._check_result('enable-failure disable',
                                   getattr(self.proxy, self.DISABLE)())
                after = self.status()
                if after['enabled']:
                    raise RuntimeError('still enabled')
            except Exception as disable_error:
                raise RuntimeError('%s; fail-closed disable also failed: %s' %
                                   (enable_error, disable_error)) from enable_error
            raise

    def disable(self):
        before = self.status()
        self._check_result('disable', getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['enabled']:
            raise RuntimeError('GL1 fast redirect remained enabled at teardown')
        return dict(before=before, after=after)


class Vel2StepFilter:
    """Fail-closed host boundary for a one-shot firmware software-step run."""
    ENABLE = 'hv_vel2_step_filter_enable'
    STATUS = 'hv_vel2_step_filter_status'
    DISABLE = 'hv_vel2_step_filter_disable'
    STATUS_FIELDS = ('active', 'status', 'steps', 'first_pc', 'last_pc',
                     'previous_pc', 'range0_hits', 'range1_hits',
                     'range_switches', 'terminal_pc', 'max_steps',
                     'range0_start', 'range0_end', 'range1_start', 'range1_end',
                     'expected_first_pc')
    DISABLED = 0
    RUNNING = 1
    TERMINAL = 3

    def __init__(self, proxy):
        self.proxy = proxy
        missing = [name for name in (self.ENABLE, self.STATUS, self.DISABLE)
                   if not callable(getattr(proxy, name, None))]
        if missing:
            raise RuntimeError('VEL2 step-filter proxy API unavailable: ' +
                               ', '.join(missing))

    def status(self):
        status = getattr(self.proxy, self.STATUS)()
        if not isinstance(status, dict):
            raise RuntimeError('VEL2 step-filter status is not a dictionary')
        missing = [name for name in self.STATUS_FIELDS if name not in status]
        if missing:
            raise RuntimeError('VEL2 step-filter status missing: ' +
                               ', '.join(missing))
        if type(status['active']) is not bool:
            raise RuntimeError('VEL2 step-filter active status is not Boolean')
        for name in self.STATUS_FIELDS[1:]:
            value = status[name]
            if type(value) is not int or not 0 <= value <= (1 << 64) - 1:
                raise RuntimeError('VEL2 step-filter status field is not u64: ' +
                                   name)
        return {name: status[name] for name in self.STATUS_FIELDS}

    @staticmethod
    def _check_result(operation, result):
        if result not in (None, 0):
            raise RuntimeError('VEL2 step-filter %s failed: %r' %
                               (operation, result))

    def prepare(self):
        try:
            before = self.status()
        except Exception as status_error:
            try:
                self._check_result('preflight recovery disable',
                                   getattr(self.proxy, self.DISABLE)())
            except Exception as disable_error:
                raise RuntimeError('%s; preflight recovery disable failed: %s' %
                                   (status_error, disable_error)) from status_error
            raise
        if before['active'] or before['status'] != self.DISABLED:
            self._check_result('preflight disable',
                               getattr(self.proxy, self.DISABLE)())
        after = self.status()
        if after['active'] or after['status'] != self.DISABLED:
            raise RuntimeError('VEL2 step filter remained armed at preflight')
        return dict(before=before, after=after,
                    stale_state_cleared=(before['active'] or
                                         before['status'] != self.DISABLED))

    def enable(self, range0, range1, terminal_pc, max_steps,
               expected_first_pc):
        values = (*range0, *range1, terminal_pc, max_steps,
                  expected_first_pc)
        if (any(type(value) is not int for value in values) or
                not 0 < max_steps <= (1 << 24) or
                not range0[0] < range0[1] or
                not range1[0] < range1[1] or
                any(value & 3 for value in
                    (*range0, *range1, terminal_pc, expected_first_pc))):
            raise RuntimeError('Invalid VEL2 step-filter bounds')
        try:
            self._check_result('enable', getattr(self.proxy, self.ENABLE)(
                *range0, *range1, terminal_pc, max_steps,
                expected_first_pc))
            status = self.status()
            if (not status['active'] or status['status'] != self.RUNNING or
                    status['terminal_pc'] != terminal_pc or
                    status['max_steps'] != max_steps or
                    status['range0_start'] != range0[0] or
                    status['range0_end'] != range0[1] or
                    status['range1_start'] != range1[0] or
                    status['range1_end'] != range1[1] or
                    status['expected_first_pc'] != expected_first_pc or
                    any(status[name] for name in
                        ('steps', 'first_pc', 'last_pc', 'previous_pc',
                         'range0_hits', 'range1_hits', 'range_switches'))):
                raise RuntimeError('VEL2 step-filter enable readback mismatch')
            return status
        except Exception as enable_error:
            try:
                self._check_result('enable-failure disable',
                                   getattr(self.proxy, self.DISABLE)())
                after = self.status()
                if after['active'] or after['status'] != self.DISABLED:
                    raise RuntimeError('still active')
            except Exception as disable_error:
                raise RuntimeError('%s; fail-closed disable also failed: %s' %
                                   (enable_error, disable_error)) from enable_error
            raise

    def disable(self):
        before = None
        errors = []
        try:
            before = self.status()
        except Exception as error:
            errors.append('stop audit failed: ' + str(error))
        try:
            self._check_result('disable', getattr(self.proxy, self.DISABLE)())
        except Exception as error:
            errors.append('disable failed: ' + str(error))
        after = None
        try:
            after = self.status()
            if after['active'] or after['status'] != self.DISABLED:
                errors.append('VEL2 step filter remained active at teardown')
        except Exception as error:
            errors.append('disable audit failed: ' + str(error))
        if errors:
            raise RuntimeError('; '.join(errors))
        return dict(before=before, after=after)


def audit_and_disable_tpidr_gl2_fast_shadow(adapter, host_shadow, register,
                                            synchronize=True):
    """Audit firmware counters/value, restore host ownership, and always disable."""
    result = {'stop_audit_attempted': True, 'host_shadow_synchronized': False,
              'disabled_at_teardown': False}
    errors = []
    try:
        audit = adapter.status()
        result['stop_audit'] = audit
        if synchronize:
            host_shadow[register] = audit['shadow']
            result['host_shadow_synchronized'] = True
            result['final_value_hex'] = hex(audit['shadow'])
    except Exception as error:
        result['stop_audit_error'] = str(error)
        errors.append('stop audit failed: ' + str(error))
    try:
        result['disable_status'] = adapter.disable()
        result['disabled_at_teardown'] = True
    except Exception as error:
        result['disable_error'] = str(error)
        errors.append('disable failed: ' + str(error))
    return result, errors
