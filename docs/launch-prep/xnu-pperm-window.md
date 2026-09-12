# XNU pmap bootstrap permission window

Attempt 67b reached a terminal WFE in early SP1 exception handling. Its original
cause was recovered from the retained debugger frame and panic varargs, not
from the WFE itself. The reported reason is `Invalid kernel stack pointer
(probable corruption or early boot).` This message does not establish stack
corruption: this early fallback is used before a current thread/kernel stack
is registered.

The recovered original exception is ESR `0x9600004f`, FAR
`0xfffffdf0006ba040`, at runtime `0xfffffe002b63cc3c` (linked
`0xfffffe000b63cc3c`), instruction `0xa900340c`, `stp x12,x13,[x0]` in
`memcpy`. It was copying 32 bytes from `0xfffffe0027044640`; the caller's
PAC-stripped return address is `0xfffffe002b80029c`.

The archived stage-1 walk maps the destination to owned physical
`0x10017ee6040`, with L3 descriptor `0x40010017ee4603`. Architectural AP permits
writes. Its SPRR index is 2; the captured final PPERM value
`0x2020a52a302abae6` selects nibble A (ordinary-world read-only) for that index.
The earlier interpretation that an address outside the kernel image was
unmapped was incorrect. Final permissions were sampled after panic handling,
so they cannot alone establish the bank state at the original store.

The pinned caller intentionally changes only index 2 from A to B (read/write),
calls memcpy, then restores B to A. Its four register sites are linked
`0xfffffe000b800260`, `0xfffffe000b80026c`, `0xfffffe000b80029c`, and
`0xfffffe000b8002a8`. Pinned m1n1's `MSR_REDIRECTS` maps
`SPRR_PPERM_EL1` (`S3_6_C15_C1_6`) to guest `SPRR_PPERM_EL12`
(`S3_6_C15_C15_7`). Native XNU continuation needs a bounded test of that
existing bank contract.

The proposed opt-in redirects only these four source-verified instructions
through an ordered state machine. It captures the full guest-bank value,
requires index 2 A, admits only the computed A-to-B full value, reads back the
write, then verifies and restores the original full A value after memcpy.
Physical EL1 PPERM, the leaf descriptor, and memcpy remain untouched. If the
run stops within the window, cleanup restores the captured guest-bank value
after VEL2 deactivation. A B readback predicts write permission from the pinned
SPRR table; reaching the second register read after memcpy is the hardware
validation that the copy actually crossed the fault.

The captured debugger/original fault frames and strings are archived as
`attempt-67b-panic-investigation.tar.gz`, SHA-256
`1d7b0026647a98aecc8a2f8ff2da5108c3e2ffd1a2bf66ed6851aaec4e1bb6d0`.
The target is being freshly rebooted for attempt 68; the diagnostic is under
implementation and replay review.


Full-suite validation caught an entry-guard regression before hardware:
a local `original` assignment in the new callback shadowed the outer guard's
instruction bytes. Renaming it preserves the existing entry-guard path.
Failure injection also exercises a successful permission write followed by
readback failure: cleanup eligibility must be set before the write, and only
cleared after verified restoration. This prevents a readback exception from
leaving the writable guest-bank state untracked.


The canonical activated suite passes 403 tests, one skipped. The flag is
`--xnu-pperm-guest-window` (pipeline key `xnu_pperm_guest_window`). Each source
instruction is replaced by a distinct exact-site HVC; its saved PC is already
after the instruction, so callbacks do not increment it again. Attempt 68 is
the first hardware validation of this ordered guest-bank window.


The helper's pinned direct caller is `_zalloc_ro_mut`. After the A restore,
it restores the saved interrupt state and returns. The current diagnostic
admits exactly one complete window; a repeat invocation is a deliberate
order stop. If hardware reaches that limit, a later bounded extension may
admit repeated complete windows while retaining the first full-A baseline
and rejecting any drift or partially restored state.


## Hardware validation — attempt 68

Run `ae0ed047-7498-41e4-be8d-d9e1ff7e8824` captured all four operations with
exact full-raw readbacks: A `0x2020a52a302abae6`, B `0x2020a52a302abbe6`,
B again after memcpy, then restored A. `memcpy_crossed=true` establishes that
the copy crossed the former fault. Physical EL1 PPERM and page tables were
not changed by the callback. No modified window remained at exit.

The same helper was invoked again and hit the deliberate one-window order
check. The original implementation labels that stop `probe-validation-error`
with `XNU PPERM callback order mismatch`; it is the bounded experiment's
repeat limit after a successful complete window, not recurrence of the copy
fault. The run captured 14278 events in 145.51 seconds, returned cleanly, and
left the proxy alive without cleanup errors.

Event-journal SHA-256:
`b698b37a6448921d59ba7207853af8041e89ba6778f83a0741f8ab40bbcf4d09`.
A finite repeated-window extension is now under validation. It must retain
the first full-A baseline, start another window only after exact restoration,
and keep cleanup effective for interruption in any later window.


The next experiment enables up to 256 complete windows through
`xnu_pperm_guest_window_limit` (default 1, accepted range 1–4096). The first
full-A value stays immutable. A later call is admitted only after a verified
A restore with matched started/completed counts; full-register drift stops.
Normal limit exhaustion has its own `xnu-pperm-window-limit` stop reason and
performs no new PPERM access. Validation failures retain the exact callback
context, and interruption cleanup remains active in later windows.


Repeated-window validation passed the fully activated discovery suite: 413
tests, no skips (`/tmp/m3-pperm-repeat-tests.log`). This includes additional
cases enabled by the activated environment; earlier canonical restricted
runs are recorded separately above. Attempt 69 is the first hardware run of
the 256-window configuration. Attempt-68 transfer archive SHA-256:
`0e42a52b028d51b4123fc3094d10ccbd55c5019c1004b7740af0092459449701`.

## Repeated-window hardware validation — attempt 69

Run `1ca8f070-5da2-4537-912e-fd5f856ff728` completed two permission windows.
Both recorded the same full A value `0x2020a52a302abae6`, the exact computed B
value `0x2020a52a302abbe6`, the same B value after `memcpy`, and an exact A
restore. The report records `started_windows=2`, `completed_windows=2`, and
`memcpy_crossed_windows=2`. No window was left modified, so cleanup correctly
performed no PPERM bank I/O. Physical EL1 PPERM remained untouched.

The 180.28-second watchdog expired after 17,576 events and 15,779 verified
SPTM callbacks. This was not a demonstrated deadloop. The terminal 123
selector-2 page mappings form a strict 16 KiB progression from
`0xfffffe4f6a100000` through `0xfffffe4f6a2e8000`, with corresponding PTE
physical addresses advancing through the same 123 pages. Earlier portions of
the final 5,000 events contain several mapping phases and some repeated
addresses; only the terminal suffix is claimed monotonic. The actual budget
event is at SPTM PC `0xfffffe00070a4254`, outside a permission window.

Guest return, all timer/redirect restorations, event-archive completion, and
proxy health passed. No XNU console bytes were emitted. Transfer archive
SHA-256 is
`82bbbb1507924004e804dbbcad922b2192aa08d9488c7a6bf5fc01debfff7f11`;
event-journal SHA-256 is
`7583b3d4a99b4b1f3a78da4497502172d79d14213e03512e01dbcf051a5afebe`.

Attempts 70 and 71 kept the 256-window limit and completed the same two exact
windows. Their 360.33- and 900.50-second watchdog stops retained advancing map
activity, clean guest return, and live proxy state. Attempt 70 recorded 650
selector-2 maps; attempt 71 recorded 658. The very small gain from another 540
seconds identified host callback latency as the practical feedback bottleneck,
not a demonstrated guest loop.

The opt-in TPIDR_GL2 firmware fast shadow then preserved this permission
evidence in attempts 72 and 73 while reaching real new stops in 39.28 and 50.03
seconds. Both again record `started_windows=2`, `completed_windows=2`, and
`memcpy_crossed_windows=2`, with the exact A-B-B-A values, physical EL1 PPERM
untouched, and no cleanup write required. The fast path handles no PPERM or GL1
traffic; those callbacks remain host-visible. See
[the fast-shadow evidence](xnu-tpidr-gl2-fast-shadow.md).
