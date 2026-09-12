# First-contact genter driver — finalized build spec (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Supersedes the address assumptions in [first-contact-spec.md](first-contact-spec.md)
and [call-abi.md](call-abi.md) with the reconciled disassembly (verified against the
SHA-matched `local/payload/sptm.macho`). This is the buildable spec for the R2
first-contact genter driver.

## Reconciled facts

- **Service dispatcher: `0xfffffe00070a4524`.** Reads guarded ESR `S3_6_C15_C10_5`,
  `& 0x1f` = call type, branches: T4 `0xa48e8` (checked first), then a config gate,
  then T0 `0xa4a14` / T1 `0xa4780` / T2 `0xa45f4` / T3 `0xa46c4`; default → `0xDEAD`.
- **`0xb0b98` is the one-shot per-CPU init** (write `TPIDR_GL2` → guarded config →
  `VBAR_GL1` → `ret`), NOT a dispatcher. `GXF_ENTER_EL1` (`S3_6_C15_C8_1`) is a
  programmable register: boot sets it to `0xb0b98` for the init genter, then at
  `0xb0c48` re-points it to `0xa4524` for steady state.
- **Type-0 path (T0 `0xa4a14`):** saves x0–x7 to the per-CPU frame, switches to the
  guarded stack, then `mov x0,x16; adr x30,#8; b →0xe8d4c`. The C service entry is
  **`0xe8d4c`** (corrected from `0xe8d8c`).
- **Non-mutation stop PC = `0xfffffe00070a4ac0`** (the `b →0xe8d4c`). Halting there
  proves enter→dispatch→type-0→about-to-call-service with the service never running;
  T0's earlier writes are SPTM-internal save-frame/stack bookkeeping (benign). For
  ZERO SPTM writes, stop at the dispatcher (`0xa4524`/after the type read `0xa452c`).

## Driver (Option B, simplified — SPTM leaves us at EL1 normal world)

attempt-21: SPTM completes init and idles at `0xfffffe00070f8b88` at **EL1 in the
normal world** (SPSR `0x400013c4`). So the normal-world caller context already exists;
we only inject a `genter`.

Build steps:
1. **Reach idle** (existing: real_guarded + GL2 shadow + A/B/C backing → 16M budget
   settles at the `0xf8b88` idle loop).
2. **Verify GXF_ENTER at idle** — read `S3_6_C15_C8_1` natively; it MUST be
   `0xa4524`. If it reads `0xb0b98`, confirm whether that's a probe shadow artifact
   (re-read after PC passed `0xb0c48`) or real; do NOT inject until it is `0xa4524`,
   or the genter lands in the init routine.
3. **Inject the genter** from the idle point: place a `genter #0` (opcode
   `0x00201420`) reachable from normal-world EL1 (pre-placed at load time before SPRR
   W^X — e.g. patch the idle-loop branch at `0xf8b8c`, which is only executed in the
   post-boot idle), set `x16 = 0` (selector; don't-care, we stop before the service),
   redirect PC to it, and resume.
4. **Single-step across the boundary:** normal→guarded world switch, land at the
   dispatcher `0xa4524`, observe the ESR type read (`0xa452c`, expect low bits 0),
   branch to T0 `0xa4a14`, and **halt at `0xa4ac0`** before the `b →0xe8d4c`.
5. **Capture the round trip:** the world switch (SPSR guarded bit), the dispatcher
   PC, the observed ESR type, the T0 per-CPU frame + guarded bank (`C10_3/5/6/7`,
   `C11_1`), and confirm the caller context capture matches the ABI.

## Non-goals (unchanged)

No service execution (`0xe8d4c` never runs), no monitor-state mutation, no kernel
launch. First contact proves the world switch, the dispatcher, and the type-0 ABI on
real hardware. Finding the kernel-launch selector by observation is the step after.

## Safety

Fresh-boot gate; bounded step budget halting at `0xa4ac0`; non-mutating by
construction; the no-power-cycle diagnostic (`el2_context_after`) rides along; a 2nd
run to test consecutive-run reuse can follow (auto-reboots to macOS if it still
fails, recover via picker — no forced power-cycle).
