# attempt-17 divert analysis — the post-genter spin at 0x100033f1a00 (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Combines the full-trace pass over attempt-17 (offline) with a source study of the
vel2 GXF/guarded-exception path. Result: a source-grounded hypothesis and two
falsifiable predictions the staged attempt-18 snapshot will decide.

## What the trace shows (certain)

From a streaming pass over the 8,311,802-event trace
(`artifacts/runs/observe-sprr/attempt-17/runs/da67557c-…/events.jsonl`):

- Exactly **one** normal→guarded transition, at index **7,786,860**. The switching
  instruction at guest VA `0xfffffe00070b0c20` transferred **directly** (one
  single-stepped instruction) to `0xfffffe00070b0b98`, and SPSR gained the guarded
  bit (`0x600003c4 → 0x604013c5`, bit `0x400000`).
- The guarded-call dispatcher `0xfffffe00070a4524` (from the virtual-GXF
  observation phase) was **never reached** (0 hits in the whole trace).
- One guarded instruction executed at `0xb0b98`
  (`msr S3_6_C15_C11_1, x0`); PC then went to physical **`0x100033f1a00`** — **not**
  to `0xb0b9c` — and spun there for **524,941** identical events to end of trace.
- Spin syndrome (EL2 view): `ESR 0xca000022`, `FAR 0x0`, `SPSR 0x604013c5`.

## What the source says (cited)

From `local/m1n1-vel2` (agent study, file:line preserved):

- **`genter` is not a vectored transfer.** It jumps to a single fixed entry
  pointer `GXF_ENTER_EL1` (`src/gxf_asm.S:45,57`; the HV mirrors this with
  `ctx->elr = cpu->gxf_enter` in `src/hv_sprr.c:808`). So the world switch already
  completed when PC reached `0xb0b98`. The subsequent divert is a **separate
  event**.
- **A guarded exception vectors through `VBAR_GL1` + the standard AArch64 offset.**
  `VBAR_GL1 = _gxf_vectors` (`src/gxf_asm.S:43`), a normal 16-entry table
  (`.align 11`, entries `.align 7` = 0x80). A **same-EL synchronous** exception
  (an `msr` faulting in guarded EL1) lands at **`VBAR_GL1 + 0x200`**; a lower-EL
  sync exception at `+0x400`. `VBAR_GL1` register is `sys_reg(3,6,15,10,2)`
  (`src/cpu_regs.h:719`); the guest's value is mirrored to `VBAR_EL12` on genter
  (`src/hv_sprr.c:787`).
- **`S3_6_C15_C11_1` (`sys_reg(3,6,15,11,1)`) is undefined anywhere in the vel2
  tree** — not a guarded-bank reg, not in `HV_VREGS`, no EL2 handler case. The
  proxyclient will not rewrite it (stays a real `msr` in SPTM); if it traps to EL2
  the dispatcher falls through `default: return false` (`src/hv_sprr.c`,
  `hv_handle_msr` `src/hv_exc.c:344-388`). It is an SPTM-specific per-CPU register
  whose source is not in this tree.
- `0x33f1a00` is a **raw physical address** in the boot/heap carveout, below the
  guest window (`+0xe000000`) and above m1n1's linked image (~0.9 MB at RAM base,
  `_va_base 0xFFFFFE0007004000`, `m1n1.ld:4`). Not statically resolvable to a
  symbol (no `build/m1n1.map`). vel2's MMU-off translation is mutually exclusive
  with the guarded path (`src/hv_vel2.c:21`), so it is not involved.
- The guarded SPSR bit `0x400000` is **not modeled in the vel2 tree** (the HV
  tracks guardedness via `ASPSR_GUARDED = BIT(0)` / `GXF_STATUS`). Its presence in
  the trace therefore indicates a **real hardware guarded world** — i.e. the
  native `genter` fired, not the emulated HVC path. This addresses the "was GXF
  truly native" caveat directly: it was.

## Hypothesis

**The divert is a guarded synchronous exception taken by the `msr S3_6_C15_C11_1`,
vectored through `VBAR_GL1 + 0x200`.** The `msr` did not retire (`+4`) but left for
a far address, which for a non-branch instruction means it faulted; guarded faults
vector via `VBAR_GL1`; same-EL sync offset is `0x200`. The vector base is pointing
into the physical boot region rather than a guest handler, so the slot at
`+0x200` is effectively a spin (`b .`) — no real guarded exception handler is
installed under the probe's staging.

That the faulting register (`S3_6_C15_C11_1`) is undefined in vel2 is consistent:
SPTM writes its own per-CPU guarded register; under our `--real-guarded` staging
that access is not permitted/backed, so the first such write in guarded world
faults immediately.

## Two falsifiable predictions for attempt-18

The exit snapshot (`report['guarded_bank_exit']`, per-register fault-tolerant)
captures `VBAR_GL1`, `GXF_ENTRY_EL1`, `ESR_GL1`, `ELR_GL1`, `SPSR_GL1`,
`ASPSR_GL1`, `GXF_PABENTRY_EL1` via their `_GL12`/`_EL12` aliases.

1. **Divert = guarded sync vector:** expect `VBAR_GL1 == 0x100033f1800`
   (`0x100033f1a00 − 0x200`). If so, hypothesis confirmed; `ESR_GL1` should name
   the `msr` as the faulting instruction and `ELR_GL1` should be `≈0xfffffe00070b0b98`.
2. **Real genter target:** expect `GXF_ENTRY_EL1 == 0xfffffe00070b0b98` (the real
   native genter landing), reconciling with the virtual-phase dispatcher
   `0xa4524` — i.e. `0xa4524` was the virtualized-model dispatcher, and the real
   fixed GXF entry is `0xb0b98`.

If prediction 1 fails, capture `GXF_PABENTRY_EL1` and check the console for
"Guest exception not handled, rebooting." to test the alternative (a stale/parked
jump target reached via a reset park in `src/start.S`).

## Implication for the phase

If confirmed, the blocker is not the genter mechanism (which works) but that **no
guarded exception handler / valid guarded per-CPU state is installed** when SPTM's
first guarded register write runs under the probe. The next design question is
whether to (a) let SPTM install its own guarded vectors/handlers earlier by
backing the pages/permissions that write needs, or (b) provide a minimal guarded
vector so the fault is observable rather than a silent spin. Both are post-attempt-18
decisions gated on the snapshot.
