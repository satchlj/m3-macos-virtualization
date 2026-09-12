# XNU entry prefix audit, 2026-09-11

This is an offline audit of the original kernelcache
`artifacts/payloads/extracted/kernelcache.macho` (SHA-256
`e342c14cd98c62a279c7ff45c8acfd69f2681ac51f029eaee244e82826cb4787`).
The Mach-O `LC_UNIXTHREAD` entry is linked at `0xfffffe000bfb0000` in
`__TEXT_BOOT_EXEC` (file offset `0x4fac000`) and runs at
`0xfffffe002bfb0000` with the observed slide. The first 512 bytes were decoded
as little-endian AArch64 words with Homebrew LLVM 23 `llvm-mc`; there was no
target access.

## Actual entry dispatch

The entry does **not** read `CurrentEL` in its first 128 instructions. Its first
dispatch is:

```asm
+0x00  bti c
+0x04  mov x8, #4
+0x08  cmp x0, x8
+0x0c  b.ne +0x24
+0x10  adrp x8, ...
+0x14  strb w2, [x8, #3936]
+0x18  mov x0, x1
+0x1c  b +0x4000
+0x20  b .
```

Thus `x0 == 4` selects a short alternate entry: it stores the low byte of
`x2`, moves `x1` to `x0`, and branches to linked `0xfffffe000bfb4000`
(runtime `0xfffffe002bfb4000`). The observed native XNU launch has `x0 == 0`,
so it takes the branch at `+0x0c` to `+0x24`. There is no entry-side
`CurrentEL` correction before this choice.

## Normal bootstrap prefix (`x0 != 4`)

The first register-sensitive instructions are:

```asm
+0x24  msr TPIDR_EL0, xzr
+0x28  msr TPIDR_EL1, xzr
+0x2c  msr TPIDRRO_EL0, xzr
+0x30  mrs x9, S3_5_C15_C5_0
+0x34  and x9, x9, #0xffffffffff0fffff
+0x38  msr S3_5_C15_C5_0, x9
+0x3c  mov x20, #0
+0x40  cmp x0, x20
+0x44  b.eq +0x4c
```

For boot CPU `x0 == 0`, execution then selects the primary path. It programs
both stack selections (`SPSel=1`, SP, then `SPSel=0`, SP), saves `x1` in
`x26` and `x2` in `x27`, and makes two calls. It then writes `VBAR_EL1`, issues
`isb`, restores `x0=x26` and `x1=x27`, and branches onward. The secondary path
starting at `+0xac` first saves `x3`, calls an initializer, reads `MPIDR_EL1`,
and searches a per-CPU table before installing its stacks.

Instructions 96 through 127 are padding `nop`s. Apart from the alternate
path's `strb`, the normal path's first potentially faulting operation is the
implementation-defined register read at `+0x30`; it occurs before stack setup,
argument preservation, or `VBAR_EL1` installation.

## Observed launch arguments

Attempt 50's verified pre-GEXIT event contains these live GPR values:

| register | value | prefix use |
| --- | --- | --- |
| `x0` | `0x0` | boot CPU selector; chooses normal primary path |
| `x1` | `0xfffffe0007098498` | preserved in `x26`, later restored to `x0` |
| `x2` | `0xfffffe00071002c0` | preserved in `x27`, later restored to `x1` |
| `x3` | `0x0` | used by the secondary-CPU path only in this prefix |
| `x4` | `0x0` | no use in the first 128 instructions |
| `x5` | `0x8` | no use in the first 128 instructions |
| `x6` | `0x32` | no use in the first 128 instructions |
| `x7` | `0x3b30` | no use in the first 128 instructions |

Attempt 48's SPTM panic text independently reports the same `x0`, `x1`, `x2`,
and `x3` values at the entry fault. This prefix therefore does not support the
older claim that entry `x0` directly holds the XNU `boot_args` pointer for this
native launch. Here `x0` is a zero selector and the first two pointer-like
arguments are `x1` and `x2`; their exact structures are not identified by this
bounded audit.

## Attempt 51 execution result

Attempt 51 (`75c5fdc7-8856-4633-ba76-c5a5afd1f549`) corrected the exact
verified launch state to physical EL1h and captured 64 bounded handoff-step
events. It reached runtime `0xfffffe002bfb453c` and stopped only because the
requested instruction budget was exhausted. This proves entry transfer and
execution well beyond the first register accesses; it is not a full XNU boot.

The observed path agrees with the static prefix:

- `+0x00..+0x0c` executed, then `x0 == 0` branched to `+0x24`.
- All three TPIDR clears at `+0x24..+0x2c` executed natively.
- `mrs S3_5_C15_C5_0` at `+0x30` executed natively and returned zero in `x9`;
  the masked write at `+0x38` also executed without an unsupported-register
  stop. The earlier anticipated trap there did not occur.
- The primary path installed both stacks, preserved `x1`/`x2` in `x26`/`x27`,
  and reached the `bl` at `+0x74`. That call entered runtime
  `0xfffffe002bfb4488`.

The called routine first built a 160-byte stack frame, then derived a
`0x20000000` kernel slide in `x19`. It formed runtime Mach-O base
`0xfffffe0027004000` in `x20`, loaded and accepted magic `0xfeedfacf`, selected
the 64-bit header size (`0x20`), and began processing the Mach-O header/load
commands. At the final event, the next PC was `+0x453c`; the preceding load had
put `0x6580` (the Mach-O `sizeofcmds`) in `w15`, while `w9` held `0x16c` (364,
the load-command count). The final event is a progressing parser state, not a
fault or idle loop.

The trace also clarifies saved-state interpretation. The prefix deliberately
executes `msr SPSel,#0`; subsequent handoff-step records therefore show mode
`...13c4` while continuing normally. That low mode value in a debug-step record
is not by itself the illegal-return state seen in attempt 48.

## Harness implications

Normalizing saved launch state from virtual `0x13c9` to physical EL1h `0x13c5`
is necessary for a legal return. Physical execution still gives `TPIDR_EL1`
and other EL1-named registers physical semantics, but attempt 51 demonstrates
that this difference does not obstruct this bounded prefix. In particular,
the implementation-defined `S3_5_C15_C5_0` read and write ran natively; they
must not be described as an unsupported-register stop or assigned a fabricated
emulated value.

Attempt 51 establishes native execution through `+0x4538` and the parser state
reported above. It does not establish that later register accesses have correct
virtual semantics. The next mismatch must be identified from a real bounded
stop or divergence beyond this point rather than predicted from the entry
prefix. No permission change follows from this audit.

## Attempt 52 parser progress

Attempt 52 (`0f754672-5880-4d4b-ae79-e00b1edaf369`) captured 4,096 handoff-step
events and stopped on its instruction budget at runtime
`0xfffffe002bfb45d4`. There were no intervening non-step traps. Most events are
in the compact load-command loop at `+0x45c8..+0x45fc`, whose relevant control
flow is:

```asm
+0x45c8  mov  x12, x28          // previous command
+0x45cc  mov  x28, x3           // advance to validated next command
+0x45d0  subs w9, w9, #1        // remaining ncmds
+0x45d4  b.eq +0x47b8
+0x45d8  ldr  w15, [x28, #4]    // cmdsize
+0x45dc  add  x3, x28, x15
+0x45e0  cmp  w15, #8
+0x45e4  ccmp x3, x14, #2, hs   // upper bound
+0x45e8  ccmp x3, x13, #0, ls   // monotonic/lower bound
+0x45ec  b.lo malformed
+0x45f0  ldr  w15, [x28]        // cmd
+0x45f4  cmp  w15, w25          // recognized command check
+0x45f8  b.eq +0x45c8
+0x45fc  cmp  w15, #25          // recognized command check
+0x4600  b.ne +0x45c8
```

At attempt 52's final event, the `subs` has reduced `w9` from 96 to **95** and
the next instruction is the loop-exit test at `+0x45d4`. The loop header was
seen 270 times, with 269 complete iterations; the pointer and command sizes
changed as commands were consumed. This is a finite, bounds-checked walk of
the Mach-O header's original 364 load commands. The high hit count is expected
and is not evidence of a corrupt pointer or stuck loop. At least roughly 95
more ordinary iterations remain, with extra work for recognized commands.

After the load-command count reaches zero, `+0x47b8` enters chained-fixup
processing. Static control flow then reaches these direct calls:

| call site | target | bounded interpretation |
| --- | --- | --- |
| `+0x495c` | `+0x50f4` | post-fixup finalization with `(1, Mach-O base, slide)` |
| `+0x4994` | `+0x4cf8` | initialization using Mach-O base, slide, and output slots |
| entry `+0x007c` | `+0x49dc` | second top-level initializer after the first call returns |

The second top-level initializer includes authenticated pointer operations and
an indirect authenticated call at `+0x4a70`. Nearby leaf helpers at `+0x5074` and
`+0x5080` read `MIDR_EL1`, but this bounded trace has not reached them and the
direct path above does not prove either helper will be called. No other `mrs`
or `msr` occurs in the statically decoded `+0x47b8..+0x4db8` continuation.
Accordingly, the earliest actual platform-register probe after clearing single
step should be reported from the next native exception; naming `MIDR_EL1` now
would be a reachability prediction rather than an observation.

## Attempt 53 first native SPTM call

Attempt 53 (`6e7002a6-ec38-4e4b-b614-541df0e6b02b`) cleared single step after
the verified prefix and stopped at the first lower-level exception. XNU had
completed the parser/initializer work, written `VBAR_EL1`, loaded selector 15
into `x16`, and executed the Apple `genter` instruction at runtime
`0xfffffe002bfb0094`. The guarded bank records the exact caller contract:

| field | value | meaning |
| --- | --- | --- |
| `ELR_GL1` | `0xfffffe002bfb0098` | XNU continuation immediately after `genter` |
| `SPSR_GL1` | `0x600013c4` | return to physical EL1t; XNU selected `SP_EL0` earlier |
| `ASPSR_GL1` | `0x2` | hardware-captured auxiliary state |
| `ESR_GL1` | `0xfe010000` | GXF genter syndrome, low-five-bit call type 0 |
| `x16` | `0xf` | native XNU service selector 15 |

SPTM entered its established dispatcher at `0xfffffe00070a4524`. Its
`mrs x8, ESR_GL1` at `0xfffffe00070a4528` had already been rewritten to the
existing synthetic Apple-register callback; the host stop has synthetic ESR
`0x5a00b028` and next PC `0xfffffe00070a452c` (`and x8, x8, #0x1f`). This is
not an unknown native XNU fault. Resuming only that verified read callback means
placing the captured `ESR_GL1` value `0xfe010000` in `x8` and continuing at
`0xa452c`; the dispatcher will observe type 0.

The established type-0 path saves `x0..x7` and the caller state, switches to
SPTM's guarded stack, moves selector `x16` into service argument `x0`, and
branches to the C service entry at `0xfffffe00070e8d4c`. Attempt 53 alone did
not identify selector 15's result contract. Attempt 54 continues beyond this call. Existing
synthetic register callbacks may expose bounded monitor state; this result does
not justify general exception emulation.

## Attempt 54 selector-15 bootstrap and next stop

Attempt 54 (`64c45ed9-cad5-4a00-9ad3-0aa683b156d9`) resumed only exact,
original-SPTM-instruction synthetic register callbacks. The offline selector
classifier resolves `0xf` as follows:

1. bits 55:48 are zero, so it is not `CALL_TXM` or `CALL_SK`;
2. bits 39:32 are zero;
3. low byte `0x0f` is not special `ENTER_GUEST` (`0x1b`), `EXIT_GUEST`
   (`0x1c`), or `CALL_SPTM_HIB` (`0x1e`);
4. the default branch at SPTM `0xe8e88..0xe8e98` selects event 2,
   `CALL_SPTM`, while preserving the full selector as the service argument.

This is XNU's native bootstrap use of the event-2 service family. Attempt 53
records the caller's continuation at entry `+0x98`; the final guarded bank in
attempt 54 instead contains `ELR_GL1=0xfffffe002bf7a7e8`, immediately after a
later selector-45 console wrapper. That final snapshot cannot establish
selector 15's return contract or prove that it redirected execution. A causal
claim about that service requires its own return events from the full trace.

XNU then progressed to runtime `0xfffffe002bf91db0`, where it directly executes:

```asm
0xfffffe002bf91da8  msr AGTCNTRDIR_EL1, xzr
0xfffffe002bf91dac  mov w8, #3
0xfffffe002bf91db0  msr AGTCNTRDIR_EL12, x8
0xfffffe002bf91db4  isb
```

The write at `0xfffffe002bf91db0` raised undefined instruction:
`ESR_EL12=0x02000000`, `ELR_EL12=0xfffffe002bf91db0`, `FAR_EL12=0`, and saved
PSTATE `0x200013c4`. XNU vectored through its installed
`VBAR_EL12=0xfffffe002b640000` and reached the exception-path park at
`0xfffffe002b691240` (`wfe; b .`), where the probe stopped. The park is a
consequence of the captured undefined register write, not a parser loop.

The preceding `S3_1_C15_C1_5` encoding is `AGTCNTRDIR_EL1`; its clear executed
natively. The faulting `S3_4_C15_C14_6` encoding is `AGTCNTRDIR_EL12` in the
pinned m1n1 register definitions. Value 3 sets the documented local bit names
`AGTCNTRDIR_DISABLE` and `AGTCNTRDIR_EL0_TRAP_CTL`; both pinned m1n1
`run_guest.py` variants also program this EL12 register to 3. That establishes
the requested value and intended register bank, but not that a physical-EL1
write may be silently redirected.

This is the earliest established post-selector-15 platform mismatch. It is a
direct, unpatched XNU implementation-register access, not one of SPTM's
verified synthetic callbacks. Any continuation needs a specific,
instruction-verified `AGTCNTRDIR_EL12 = 3` handling rule; the attempt does not
support blanket unknown-instruction or exception emulation.
