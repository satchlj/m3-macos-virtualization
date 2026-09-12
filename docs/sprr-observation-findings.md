# What the observation-only SPRR run showed

> Historical research context. Status and proposed next steps below describe the
> original investigation. See [current project status](STATUS.md) for later
> results and remaining milestones.

Attempt `sprr-observation-v1/d5dc52d5` (USB host worktree, commit daaeb84,
16,777,216-step budget, `observe_sprr` + `stop_on_vector_entry`) reproduced
the two live TTBR switches, then continued past the point where every earlier
run stopped. Sequence after the monitor believed SPRR was on:

1. Event 7,786,591: `SPRR_CONFIG_EL1 = 1` staged, not enforced
   (`observed-sprr-config`, hardware SPRR left off).
2. It then wrote `SPRR_PPERM_EL1 = 0x2020a52a302abaf5` and
   `SPRR_UPERM_EL0 = 0x2010002030100000` (staged), compared PPERM against a
   constant, and built `x0 = 0x40010`.
3. Twenty instructions later (event 7,786,611) it branched to `VBAR_EL12`
   (`0xfffffe00070ad000`), then into the synchronous-from-current-EL vector at
   `VBAR+0x200`, and spun there re-taking the same fault.

The fault is a level-3 data permission fault on a read:
`ESR_EL12 = 0x9600000f` (EC 0x25, DFSC 0x0f), `FAR_EL12 = 0xfffffe00070ae018`,
`ELR_EL12 = 0xfffffe00070ad208`, `SPSR_EL12 = 0x606013c5` (EL1h, PAN set). The
vector handler at `0xad200` itself reads a pointer near the faulting page, so
it re-faults immediately: a monitor fault loop, not progress.

## Why this is the expected result, not a regression

Hardware SPRR was only staged, so the CPU interpreted the monitor's stage-1
leaves with ordinary ARM AP/UXN/PXN semantics. The faulting leaf
`0x40100150dc603` reads natively as kernel read/write, no EL0, executable. The
monitor programmed `SPRR_PPERM_EL1`/`SPRR_UPERM_EL0` expecting those same leaf
bits to be reinterpreted as an SPRR permission index. Native and SPRR-effective
permissions therefore disagree, and the monitor's own code takes a permission
fault on its first data access under the new regime. This is the precise
mismatch the observation was designed to expose: continuing past SPRR enable
requires interpreting leaf permissions through the SPRR registers, not copying
upstream's shadow-table machinery wholesale.

A read-only EL2 snapshot of the idle machine afterward
(`hardware-sprr-state.json`) confirms `SPRR_CONFIG_EL1 = 0`, `GXF_CONFIG = 0`,
`apple_sysregs_unlocked` and `mmu_sprr` true, and that `SPRR_PPERM_EL1` /
`SPRR_UPERM_EL0` are inaccessible while SPRR is off (reads trap), which is why
the run had to stage rather than read them back. The guest exception registers
in that snapshot still hold the fault, and the proxy survived.

## Next

Decode the faulting leaf's SPRR-effective permission offline
([sprr-leaf-permissions.md](sprr-leaf-permissions.md)) against the recorded
`PPERM_EL1`/`UPERM_EL0`, confirm the native/SPRR divergence exactly, and use it
to scope the smallest permission model that lets the monitor's own accesses
succeed. No hardware SPRR enable is attempted until that model validates
offline against the captured tables.

## attempt-5: full guarded-world SPRR bring-up observed (2026-09-10)

With `--stage-el2-config` added, the monitor advanced past the SPRR enable that
stopped earlier attempts and executed its complete bring-up in one tight
sequence (trace indices 7,786,815–7,786,871), captured whole:

- `SPRR_CONFIG_EL1 ← 1` (enable), then populate: `SPRR_UPERM_EL0 =
  0x20100000_00000000`, `SPRR_PMPRR_EL1 = 0x40010`, `SPRR_PPERM_EL1 =
  0x20218000…7157`.
- `SPRR_CONFIG_EL1 ← 0xfb` = enable + lock_config + lock_perm +
  lock_kernel_perm (unknown bits 0xc8).
- `GXF_CONFIG_EL1 ← 1`, set `GXF_PABENTRY_EL1`/`GXF_ENTRY_EL1`, **genter**,
  set `TPIDR_GL2`.
- Inside guarded execution: rewrite `SPRR_PPERM_EL1 = …7142`, then
  `SPRR_CONFIG_EL1 ← 0xff` (unknown bits 0xcc).

`sprr_observation.enforced` stayed `false`: hardware SPRR is never actually
enabled, so the monitor believes it is running under a locked permission
regime that the host is only recording. The permission-table values above are
now captured for offline leaf decoding
([sprr-leaf-permissions.md](sprr-leaf-permissions.md)).

The run then stopped on a data abort (ESR `0x93c98005`) dereferencing a pointer
into IPA `0x211050218`, memory outside the isolated guest window — a
supply-memory dependency, not a permission-semantics one. The retained attempt-5
report contains the full stop analysis; raw evidence remains outside Git.

## attempt-6: exception handler depends on SPRR to read its own text (2026-09-10)

Backing the single faulted page (`--back-page=0x211050000`, zeroed) let the
monitor advance +280 steps, then it took a synchronous exception. Its exception
handlers (VBAR_EL12 +0x000 and +0x200) both start with `adrp x8,#4096; add
x8,x8,#24; ldr x8,[x8]`, loading a context pointer from `0xfffffe00070ae018` —
which lives in the same 16KB `__TEXT_EXEC` page as the handler code
(`0xfffffe00070ac000`). With hardware SPRR off that load permission-faults
(EC 0x25, DFSC L3), re-enters the same-EL sync handler, and refaults: an
unbreakable loop. The monitor relies on SPRR to permit reading data embedded in
its executable segment.

Not yet leaf-proven: the final-`ttbr1` leaf for that page was not among the
retained `tables/*.bin`; the switch-time leaf we could decode grants kernel read
under both native and SPRR. Capturing that leaf and decoding it with
[sprr-leaf-permissions.md](sprr-leaf-permissions.md) against the captured
`PPERM_EL1 = 0x2020a52a302abae6` / `UPERM_EL0 = 0x2010002030100000` is the
confirming step. The retained attempt-6 report contains the full stop
analysis, the artifact caveat, and the refined next decision.

## Correction from attempt-7: the exception-path fault was not an SPRR divergence

attempt-7 captured the faulting leaf and the clean first-entry syndrome and
overturns the attempt-6 reading. The leaf for `0xfffffe00070ac000`
(`0x40100150ac603`) permits kernel READ under native, ordinary-SPRR and
guarded-SPRR alike (only EXECUTE differs by world), so the handler's read of
`0xae018` did not permission-fault for lack of SPRR. The true trigger, captured
with zero batch overshoot, is `ESR_EL12 = 0x2000000` (EC 0, undefined), `FAR 0`,
at `msr S3_1_C15_C8_2` — a native write to an unstaged Apple guarded register
that is undefined because GXF was only virtualized. The blocker is guarded-world
state, not SPRR permission enforcement. The retained attempt-7 report contains
the complete decode and syndrome evidence.
