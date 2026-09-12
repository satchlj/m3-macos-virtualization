# SPDX-License-Identifier: MIT
# Copyright The Asahi Linux Contributors (upstream portions).
# See repository LICENSES.md and THIRD_PARTY_NOTICES.md.
"""Source-pinned three-site HVC accelerator for the Phase 5.3 retype wrapper.

This module deliberately contains no transport or hardware access.  Integration
code supplies a word reader, applies the returned rewrite plan, and feeds
observed wrapper HVCs to :class:`RetypeHvcStateMachine`.
"""
from dataclasses import dataclass


HVC_BASE_WORD = 0xd4000002
HVC_IMMEDIATE_MASK = 0xffff
MAX_RETYPE_CALLS = 64
PAC_ADDRESS_BITS = 40


@dataclass(frozen=True)
class RetypeHvcSite:
    phase: str
    runtime_pc: int
    linked_pc: int
    source_word: int
    hvc_immediate: int

    @property
    def post_hvc_pc(self):
        """ELR observed by the VHE handler after the rewritten instruction."""
        return self.runtime_pc + 4

    @property
    def hvc_word(self):
        return encode_hvc(self.hvc_immediate)


PRE_SITE = RetypeHvcSite(
    phase='PRE',
    runtime_pc=0xfffffe002bf7a4b8,
    linked_pc=0xfffffe000bf7a4b8,
    source_word=0x910003fd,
    hvc_immediate=0x6130,
)
POST_SITE = RetypeHvcSite(
    phase='POST',
    runtime_pc=0xfffffe002bf7a4cc,
    linked_pc=0xfffffe000bf7a4cc,
    source_word=0x910003bf,
    hvc_immediate=0x6131,
)
GENTER_SITE = RetypeHvcSite(
    phase='GENTER',
    runtime_pc=0xfffffe002bf7a4c0,
    linked_pc=0xfffffe000bf7a4c0,
    source_word=0xd2800030,
    hvc_immediate=0x6132,
)
RETYPE_HVC_SITES = (PRE_SITE, GENTER_SITE, POST_SITE)


def encode_hvc(immediate):
    """Encode ``hvc #immediate`` after validating the architectural imm16."""
    if type(immediate) is not int or not 0 <= immediate <= HVC_IMMEDIATE_MASK:
        raise ValueError('HVC immediate must be an unsigned 16-bit integer')
    return HVC_BASE_WORD | (immediate << 5)


def canonicalize_pac_return(value, expected_pc):
    """Reconstruct the canonical XNU VA while retaining exact low VA bits."""
    if type(value) is not int or type(expected_pc) is not int:
        raise ValueError('PAC return inputs must be integers')
    if not 0 <= value < 1 << 64 or not 0 <= expected_pc < 1 << 64:
        raise ValueError('PAC return inputs must be unsigned 64-bit values')
    mask = (1 << PAC_ADDRESS_BITS) - 1
    return (expected_pc & ~mask) | (value & mask)


def source_pinned_rewrite_plan(read_linked_word):
    """Return all rewrites only if every linked source word still matches.

    Verification is completed for the entire three-site set before a plan is
    returned, allowing the caller to avoid a partially verified rewrite.
    Each plan entry is ``(linked_pc, source_word, hvc_word)``.
    """
    observed = []
    for site in RETYPE_HVC_SITES:
        word = read_linked_word(site.linked_pc)
        if type(word) is not int or not 0 <= word <= 0xffffffff:
            raise ValueError('%s linked word reader returned a non-u32 value' %
                             site.phase)
        observed.append((site, word))
    for site, word in observed:
        if word != site.source_word:
            raise ValueError(
                '%s source drift at linked %#x: expected %#010x, got %#010x' %
                (site.phase, site.linked_pc, site.source_word, word))
    return tuple((site.linked_pc, site.source_word, site.hvc_word)
                 for site, _ in observed)


def verify_hvc_rewrites(read_word, *, runtime=False):
    """Verify the exact accelerator words at linked or runtime addresses."""
    for site in RETYPE_HVC_SITES:
        pc = site.runtime_pc if runtime else site.linked_pc
        word = read_word(pc)
        if word != site.hvc_word:
            raise ValueError(
                '%s HVC rewrite mismatch at %s %#x: expected %#010x, got %r' %
                (site.phase, 'runtime' if runtime else 'linked', pc,
                 site.hvc_word, word))
    return True


class RetypeHvcStateMachine:
    """Fail-closed PRE/GENTER/POST ordering for at most 64 wrapper calls."""

    def __init__(self, max_calls=MAX_RETYPE_CALLS):
        if type(max_calls) is not int or not 1 <= max_calls <= MAX_RETYPE_CALLS:
            raise ValueError('max_calls must be an integer in [1, 64]')
        self.max_calls = max_calls
        self.completed_calls = 0
        self.expected_phase = 'PRE'
        self.failed = False

    def observe(self, post_hvc_pc, instruction_word):
        """Consume one exact rewritten wrapper site and return its transition."""
        if self.failed:
            raise RuntimeError('retype HVC state machine already failed closed')
        if self.expected_phase == 'PRE' and self.completed_calls >= self.max_calls:
            return self._fail('retype HVC call limit reached')

        phases = {item.phase: item for item in RETYPE_HVC_SITES}
        site = phases[self.expected_phase]
        observed = next((item for item in RETYPE_HVC_SITES
                         if post_hvc_pc == item.post_hvc_pc), None)
        if observed is not None and observed is not site:
            return self._fail(
                'retype HVC order violation: expected %s, observed %s' %
                (site.phase, observed.phase))
        if post_hvc_pc != site.post_hvc_pc:
            return self._fail(
                'retype HVC post-PC drift for %s: expected %#x, got %#x' %
                (site.phase, site.post_hvc_pc, post_hvc_pc))
        if instruction_word != site.hvc_word:
            return self._fail(
                'retype HVC word drift for %s: expected %#010x, got %r' %
                (site.phase, site.hvc_word, instruction_word))

        call_index = self.completed_calls + 1
        if site is PRE_SITE:
            self.expected_phase = 'GENTER'
        elif site is GENTER_SITE:
            self.expected_phase = 'POST'
        else:
            self.completed_calls += 1
            self.expected_phase = 'PRE'
        return {
            'phase': site.phase,
            'call_index': call_index,
            'completed_calls': self.completed_calls,
            'next_phase': self.expected_phase,
            'at_limit': (self.completed_calls == self.max_calls and
                         self.expected_phase == 'PRE'),
        }

    def snapshot(self):
        return {
            'max_calls': self.max_calls,
            'completed_calls': self.completed_calls,
            'expected_phase': self.expected_phase,
            'failed': self.failed,
        }

    def _fail(self, message):
        self.failed = True
        raise ValueError(message)
