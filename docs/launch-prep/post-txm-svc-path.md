# Post-TXM return and the XNU GEXIT handoff

> Superseded by attempt 51: the `0x13c9` native return caused an illegal-return
> state (`0x1013c4`). Normalizing it to physical EL1h `0x13c5` cleared the fault
> without permission changes and established actual XNU instruction execution.
> See [the mode audit](xnu-gexit-mode-audit.md). The account below preserves
> attempts 48–49 and must not be read as proof of their legal mode transition.

Attempt 48 establishes the late handoff mechanism. It is a native guarded
exit, not an `eret`. SPTM prepared the BootKC entry, executed `gexit`, and then
reported a synchronous instruction abort at that exact entry. No XNU
instruction is known to have retired.

## TXM service-return sequence

TXM's ordinary service wrappers return through SPTM state 14, event 5, whose
action ends at runtime `0xfffffe00070a4ed8`. The rewritten `eret` traps at
`0xfffffe00070a4edc` and returns to the wrapper's `retab`. On the normal main
path the expected interior return sites are:

| TXM runtime return | Selector | Attempt-48 count | Resume policy |
| --- | ---: | ---: | --- |
| `0xfffffe0017068010` | `0x100000001` | 1 | one bootstrap return |
| `0xfffffe00170532d8` | `0x100000003` | 42 | verified, bounded repeats |
| `0xfffffe00170532ec` | `0x100000002` | 2 | two calls on this main path |

The selector-3 stub has one static direct caller, but that is not a dynamic
call-count bound. Attempt 48 returned through it 42 times: two times with
`SPSR_GL1 = 0x200013c0`, eight with `0x600013c0`, then 32 with
`0x200013c0`. These were all verified native resumes. The repeated service is
part of progressing initialization, not evidence of a loop at the `retab`.
Use a reported per-site counter and a conservative ceiling; the current limit
of 64 occurrences at this site contains the observed path without accepting an
unbounded return stream.

The two selector-2 calls are consecutive calls in TXM main. An address-only or
consume-once allowlist is also wrong for `0xfffffe00170532ec`; this observed
main path needs two returns and the preceding natural selector-2 service.

TXM then reaches its selector `0xfd00000000` return/yield wrapper. SPTM decodes
the `0xfd` class at runtime `0xfffffe00070a6450` and dispatches event 5. From
state 8, event 5 transitions back to state 5 (`STATE_XNU`) through action
`0xfffffe00070a4478`. This is a state transition out of TXM, so an ordinary
`eret` back to TXM's `0xfffffe0017053328` would be unexpected.

## Exact launch trampoline

Late setup calls runtime `0xfffffe00070a5210` from
`0xfffffe00070bff20`. The trampoline does the following:

| Runtime PC | Operation | Attempt-48 observation |
| --- | --- | --- |
| `0xfffffe00070a5234` | load global `0xfffffe0007098930` | candidate BootKC entry |
| `0xfffffe00070a5238` | write `ELR_GL1` | trap resumes at `0xa523c`; value `0xfffffe002bfb0000` |
| `0xfffffe00070a5248..5254` | form `0x13c1 | CurrentEL`, write `SPSR_GL1` | trap resumes at `0xa5258`; value `0x13c9` |
| `0xfffffe00070a525c` | clear `ASPSR_GL1` | trap resumes at `0xa5260`; value 0 |
| `0xfffffe00070a5260` | Apple word `0x00201400` | native `gexit` |

The observed `0x13c9` is the exact launch value for this path. Tests of this
trampoline must not require the `0x13c0` used by the earlier TXM-entry `eret`.

There is no `eret-guarded` event for this transfer because real-guarded mode
deliberately leaves `0x00201400` native. Only architectural `eret` instructions
are rewritten to `HVC #0x4800`. Native `gexit` switches from guarded SPTM to the
normal guest using the just-written GL1 banks without a host callback.

## What attempt 48 proves

After the `gexit`, SPTM's guarded synchronous-exception path at runtime
`0xfffffe00070a65d0` saved the incoming context and reached its exception
classification around `0xfffffe00070a6728`. The panic diagnostic is:

```
Synchronous exception taken from guest before XNU bootstrap
pc 0xfffffe002bfb0000, lr 0x0
esr 0x8600000f, far 0x0
```

`ESR 0x8600000f` is EC `0x21`, an instruction abort from the same exception
level, with IFSC `0x0f`, a level-3 permission fault. The fault PC exactly equals
the value SPTM loaded from its BootKC-entry global. Thus:

1. SPTM prepared a BootKC/XNU handoff at the exact mapped entry.
2. Native `gexit` transferred control to that entry.
3. The first instruction fetch faulted on execute permission; no XNU
   instruction is established as retired.

This supersedes treating `0xfffffe00070a4e44` as the XNU launch. That earlier
`eret` loads global `0xfffffe0007098928` and enters TXM.

## Minimal observation hook

The safest hook requires no new code rewrite. The write to `ASPSR_GL1` at
`0xfffffe00070a525c` already traps through the real guarded register redirect,
and the callback's continuation PC is exactly `0xfffffe00070a5260`, immediately
before native `gexit`.

At that one exact continuation, the probe can read redirected `ELR_GL1` and
`SPSR_GL1`, run the existing mapped-entry and byte classifier, and record a
`gexit-handoff` with `via = native GEXIT pending`. It should then resume the
untouched `gexit`. This preserves native guarded semantics and avoids a
one-shot executable-code repair or a host-side emulation of GXF.

Classification should distinguish these milestones:

- Before resuming `gexit`: `handoff-xnu-entry` means the handoff is prepared.
- A later exception whose saved guest PC is the entry proves control transfer.
- Only a trap after the entry, or another reliable retirement observation,
  proves XNU instruction execution.

The attempt-48 permission abort is a launch failure after control transfer, not
an unclassified SPTM `eret` target.

## Attempt 49 clean launch gate

Attempt 49 (`10e559ef-3a8c-495f-b52a-b6a05accc168`) implemented the hook at
the existing `ASPSR_GL1` redirect and stopped before executing `gexit`:

| Field | Verified value |
| --- | --- |
| stop reason | `handoff-xnu-entry` |
| source PC | `0xfffffe00070a5260` |
| image / segment | kernelcache / `__TEXT_BOOT_EXEC` |
| runtime / linked PC | `0xfffffe002bfb0000` / `0xfffffe000bfb0000` |
| physical address | `0x10013610000` |
| saved PSTATE | `0x13c9` |
| first 32 bytes | `5f2403d5880080d21f0008ebc1000054682400f002813d39e00301aaf90f0014` |

The mapped entry and bytes matched the pinned kernelcache. The 300-second
watchdog did not fire, guest cleanup completed, and the proxy answered after
exit. This is the reproducible pre-transfer gate; attempt 48 supplies the
independent evidence that resuming the same native `gexit` reaches the entry.

## Strict stop and resume rules

- Resume the TXM bootstrap return once. Resume selector-3 only through the
  exact verified site and predicates, with its per-site count reported and a
  conservative ceiling (64 contains attempt 48's 42 returns).
- Resume the selector-2 return exactly twice, in order, with matching selector,
  original `retab` bytes, mapped executable ownership, and expected PSTATE.
- Stop on selector-4, `0xfe`, or `0xff` paths unless live context proves an
  expected branch. Stop if selector `0xfd` returns ordinarily to TXM.
- Resume TXM entry only for the verified initial launch. Stop on unexplained
  TXM re-entry after its completion transition.
- At the GEXIT hook, require target `0xfffffe002bfb0000`, mapped kernelcache
  ownership, exact entry and bytes, and `SPSR_GL1 = 0x13c9`. Any mismatch is an
  unclassified handoff and must not be resumed automatically.
- Normalize rewritten-ERET reports as `origin = trap_pc - 4`. Do not apply that
  normalization to the pre-GEXIT register-write hook, whose continuation PC is
  the native instruction itself.
