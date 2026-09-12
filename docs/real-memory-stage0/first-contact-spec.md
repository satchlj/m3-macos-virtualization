# First real genter — contact spec (2026-09-10, final prep)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Tightly-bounded consolidation of what a first real guarded call needs, so the
next step is building, not more analysis. Draws on
[call-abi.md](call-abi.md), [genter-driver-design.md](genter-driver-design.md),
and [sprr-permission-model.md](sprr-permission-model.md).

## Objective and the safety realization

Make first contact with the guarded-call interface: a real `genter` from a
normal-world stub, and **observe the round trip** (world switch → dispatcher →
return), not invoke a service.

Key realization that removes the "pick a non-mutating selector" problem: the HV
single-steps at EL2, and `GXF_ENTRY` (the dispatcher at `0xa4524`) is the **first
instruction executed after `genter`**. The type-0 path does not mutate anything
until it calls the C service handler (`b →0xe8d8c`, ~30 instructions in). So if
we **single-step and stop at/after the dispatcher and before that `b`**, first
contact is **non-mutating by construction, regardless of selector**. The selector
value only matters once we let the service run — a later step.

## Normal-world context to construct (Option B)

`genter` auto-captures the caller into the GL bank, which the type-0 path reads:
caller PC → `ELR_GL1` (`S3_6_C15_C10_6`), PSTATE → `SPSR_GL1` (`C10_3`), class →
`ESR_GL1` (`C10_5`); `SP_EL0` is also read. GPRs (x16 = selector, x0–x7 = args)
persist across the world switch. So the synthetic normal-world entry needs:

- A valid EL1h PSTATE and a PC at the stub.
- The stub mapped **executable in the normal world's translation** under real
  SPRR (index-0 text class: guarded RX / ordinary R — so it must be normal-world
  executable; confirm the stub page's leaf class at setup).
- `SP_EL0`/`SP_EL1` set to valid stack.
- `x16` = a selector value (any; we stop before it is honored), `x0–x7` = zero.
- `genter #imm` — the immediate that yields guarded-ESR type 0. **Determine the
  type-0 immediate empirically at first contact**: single-step shows the
  dispatcher reading `ESR_GL1 & 0x1f`; pick the immediate that lands on type 0.
  (Static genter-immediate→ESR mapping is hardware and unverified; observing it
  is cheaper and certain.)

## SPRR / GXF state

- **Un-virtualize GXF**: stop rewriting `genter`/`gexit`; real `GXF_CONFIG`.
- **Enable real SPRR** per the finalized go-conditions: reproduce
  `CONFIG 0x1→0xfb→genter→0xff` with the captured `PPERM/UPERM/PMPRR`; validate
  the six leaf classes at the **enable-point** ttbr snapshot (state mutates
  between passes); confirm no user access.
- **R1 real backing**: A `0x211050000:3`, B `0x211e40000:3`, C `0x211f00000:17`.

## Observability plan (staging stream is gone under real GXF)

- EL2 **single-step across the `genter` boundary** — watch the world switch and
  each dispatcher instruction (this is also the safety stop).
- Snapshot the **guarded per-CPU frame** (`(S3_6_C15_C11_1)+0x2608`) and the GL
  bank (`C10_3/5/6/7`) before and after `genter`.
- Keep a bounded **step budget that halts at/before `0xe8d8c`** so no service
  runs.
- Read back the observed type (`ESR_GL1 & 0x1f`) and the caller capture to
  confirm the ABI on real hardware.

## Remaining build items (then first-contact hardware run)

1. Probe: an **un-virtualize-GXF** mode and a **real-SPRR-enable** path (exact
   sequence/values, enable-point validation) — the biggest new code.
2. Probe: **Option-B normal-world stub + context** construction from EL2.
3. **Reversibility rehearsal** (hardware): confirm clean HV exit and installed
   boot intact with real SPRR/GXF enabled but the stub halted before any service.
4. First-contact run: fresh-boot gate → enable → `genter` → single-step to the
   dispatcher → halt before `0xe8d8c` → dump captures. Bounded, non-mutating.

## Explicit non-goals for first contact

No service execution, no monitor-state mutation, no kernel launch. First contact
proves the world switch, the dispatcher, and the ABI on real hardware. Invoking a
real service (and finding the kernel-launch selector by observation) is the step
after.
