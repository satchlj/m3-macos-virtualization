# SPTM guarded-call ABI — dispatch map (2026-09-10, sub-step 1)

> **Correction (2026-09-10, verified disassembly):** the C service entry is `0xe8d4c`, not `0xe8d8c` (that is 0x40 bytes inside it); the non-mutation stop PC is `0xa4ac0` (the `b →0xe8d4c` in T0). Also `GXF_ENTER_EL1` is reprogrammed during boot (`0xb0b98` init → `0xa4524` dispatcher). See [first-contact-build-spec.md](first-contact-build-spec.md).


Offline disassembly (read-only, verified payload via `trace_disassembly`) of the
GXF guarded-call dispatcher and its five typed handlers, following the wake path
([wake-path.md](wake-path.md)). Addresses are `sptm/__TEXT_EXEC` (image virtual
base `0xfffffe0007004000`). Guarded system registers seen:
`S3_6_C15_C10_3` = guarded SPSR, `…C10_5` = guarded ESR, `…C10_6` = guarded ELR,
`…C10_7` = guarded FAR; `…C8_0` = GXF_STATUS; `…C11_1` = guarded per-CPU base.

## Entry and type dispatch (`GXF_ENTRY_EL1 = 0xa4524`)

`genter` lands here; the dispatcher reads the guarded ESR (`S3_6_C15_C10_5`) low
5 bits as a call **type** and routes to five handlers (default → `0xDEAD` panic):

| Type | Handler | Role |
|-----:|---------|------|
| 0 | `0xa4a14` (T0) | **Guarded call with arguments** — saves x0–x7 |
| 1 | `0xa4780` (T1) | Guarded exception entry (callee-saved only) |
| 2 | `0xa45f4` (T2) | Guarded exception entry |
| 3 | `0xa46c4` (T3) | Guarded exception entry |
| 4 | `0xa48e8` (T4) | Cross-CPU config sync (CAS bit 15 of a global halfword) |

The dispatcher checks type 4 first, then a config gate (`tbz w9,#15` on the
halfword at `adrp #376832 + 12`), then 0/1/2/3. T4 compare-and-swaps bit 15 of
that same halfword (`mov w8,#0x8000; cas …; dmb ish`) — a coordinated mode/state
flag across CPUs, not a per-call service.

## The call path (T0, type 0)

T0 is the real service call. It uses the guarded per-CPU frame at
`(S3_6_C15_C11_1)+0x2608` with a nesting counter at `+56` and register save
regions selected by depth (`+64` args, `+128`/`+312` callee-saved):

1. Save **x0–x7** (call arguments) at frame `+64`, then x19–x30 and d8–d15;
   bump the nesting counter; save guarded SPSR/SP_EL0/ELR into the frame.
2. Switch SP to the guarded stack (`[base+32]`), push a frame.
3. `mov x0, x16; adr x30, #8; b →0xe8d8c` — call the **C service handler** with
   `x0` = the call **selector** (passed by the caller in x16).
4. On return (`x20 = x0` result), reconstruct the caller's EL1 exception state
   from the guarded registers (`C10_6→ELR_EL1`, `C10_3→SPSR_EL1`, `C10_5→ESR_EL1`,
   `C10_7→FAR_EL1`, `C15_C1_1→HPFAR_EL2`, `C15_C0_2→AFSR1_EL2`) and gexit back to
   the kernel with the result. A 2-bit return-disposition field (`x1 & 3`, `==3`)
   selects the full-restore return path.

So the SPTM call ABI is: **kernel sets a selector in x16 (+ args in x0–x7),
executes `genter` with guarded-ESR type 0, and SPTM returns a result in x0 via
gexit.** T1–T3 are guarded exceptions (no args); T4 is a config-sync op.

## The C service handler (`0xe8d8c`) — heavily inlined, dispatch is gexit-terminal

`0xe8d8c` is called with the "must-not-return" idiom (`adr x30,#8; b …; brk` — the
return slot in T0 is the `0xDEAD` panic), so the service is expected to **gexit to
the kernel**, not return to T0. The function is dominated by inlined
instrumentation: a logging/validation preamble (message-arg array, conditional
`bl`, skipped when a debug flag is clear) and a small lookup whose 9-entry table
at `0xfffffe000701d7b8` holds **packed non-pointer values**
(`0x001000000000e9c5`, `…e9d4`, … — bit 52 set, low bits ~`0xe9xx`, i.e. string
or descriptor offsets), **not** handler code pointers. So that table is a
diagnostic/message table, and this function is instrumentation around the service,
not the clean per-selector switch. The real service dispatch is deeper and
terminates in a gexit.

## What is solidly established vs. still open

Established (actionable for the genter driver):
- Entry = `genter`, guarded-ESR **type 0**, **selector in x16**, **args in x0–x7**,
  **result in x0** returned via gexit; types 1–3 are guarded exceptions, type 4 is
  a config-bit-15 CAS.
- The type-0 path saves the kernel context to the guarded per-CPU frame, runs on
  the guarded stack, and the service is gexit-terminal.

Still open (deeper RE, a dedicated follow-on — not a one-pass task):
- The exact per-selector service map, including which selector (if any) launches
  the kernel below SPTM. The dispatch is obscured by heavy inlining and
  instrumentation; decoding it needs careful multi-pass work or, more cheaply,
  **observing the first genter a real kernel issues** once the genter driver runs.
- The selector register convention (x16) should be reconfirmed against a real call.

## What this fixes for Phase 2 / R2

To drive a real call we now know the exact shape: perform a real `genter` from a
lower EL with guarded-ESR **type 0**, selector in **x16**, args in **x0–x7**. This
is the concrete target for the "genter driver" sub-step of
[../real-memory-phase-plan.md](../real-memory-phase-plan.md). It requires real
guarded execution (real SPRR), so the SPRR go-conditions still gate it.
