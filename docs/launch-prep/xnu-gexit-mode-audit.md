# XNU launch state audit, 2026-09-11

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Attempt 50 (`69692c95-eb31-4e6d-aaee-5b8ebf69d896`) captured the entry leaf
and live guest permission aliases at the existing pre-GEXIT trap. The leaf is
SPRR index 10, PPERM nibble 5, UPERM nibble 0. The pinned permission model gives
privileged RX in both worlds and no unprivileged access. WXN is clear. This
does not justify changing page permissions.

The saved launch PSTATE is `0x13c9` (virtual EL2h), formed by SPTM from
`0x13c1 | CurrentEL`. The synthetic `CurrentEL` returns 8, while the monitor
physically executes at EL1. The runtime's `vel2_state.c:exception_return`
normally maps either virtual level to physical EL1h. Native GEXIT bypasses
that synthetic return handler.

Attempt 48's exception bank saved `SPSR_GL1=0x1013c4`: the illegal-return bit
is set and the mode remains EL1t. Its reported instruction-permission abort
at the entry therefore cannot be treated as evidence of a legal world/mode
transition. The former claim that native GEXIT successfully switched into XNU
was too strong; it reached the target PC with invalid return state and no
instruction retirement.

The bounded next experiment normalizes only this exact, image-verified launch
state from `0x13c9` to physical `0x13c5`, adds the diagnostic single-step bit,
completes the pending ASPSR clear, and resumes the original GEXIT. It changes
no page permissions. A step reported at the entry proves only transfer; a
subsequent step after an XNU instruction is needed to establish execution.

`--xnu-steps` requires native TXM continuation and a budget of 1–4096 events.
The original pre-GEXIT stop remains the default. Missing permission capture,
non-executable privileged entry, changed payload bytes, or unexpected saved
launch state prevents automatic continuation.

## Hardware validation

Attempt 51 (`75c5fdc7-8856-4633-ba76-c5a5afd1f549`) cleared the entry fault
with the mode correction alone. It captured the entry at `0xfffffe002bfb0000`
with PSTATE `0x13c5`, then `+4`, `+8`, `+0xc`, and the normal entry branch
to `+0x24`. All 64 recorded events were steps; the final PC was
`0xfffffe002bfb453c`. The guarded bank retained ASPSR zero. XNU instruction
execution is established; a complete macOS guest boot is not.

## First native continuation

Attempt 52 (`0f754672-5880-4d4b-ae79-e00b1edaf369`) captured 4096 steps in
a progressing Mach-O parser. Attempt 53 (`6e7002a6-ec38-4e4b-b614-541df0e6b02b`)
then ran natively after a 64-event verified prefix and reached XNU's first
SPTM call, selector 15. Attempt 54 (`64c45ed9-cad5-4a00-9ad3-0aa683b156d9`)
allowed the existing SPTM callbacks only when their HVC exactly matched the
rewritten pinned source instruction. XNU continued into its startup code and
reported an undefined `AGTCNTRDIR_EL12` write before serial initialization.

The early character output is recoverable from SPTM selector `0x2d` calls:

```text
panic: Undefined kernel instruction: pc=0xfffffe002bf91db0 instr=d51cfec8 @sleh.c:1869
Kernel panicked very early before serial init, spinning forever...
```

`scripts/extract_xnu_console.py` decodes these events from a report or a full
indexed event archive. The pipeline saves `xnu-console.txt` automatically.
The timer-register compatibility experiment is independently documented in
the entry-prefix audit and recorded per run; it requires exact source, site,
value and guest-bank checks plus restoration after guest return.

## Guest timer mapping validated

Attempt 55 (`18f588d9-a249-4358-9042-4a5e9a693861`) reached the exact
substituted HVC, but its handler rejected the syndrome because the expected
constant omitted the architectural instruction-length bit. No bank write
was performed. Correcting the exact syndrome to `0x5a0060b8` allowed
attempt 56 (`b4d1c7aa-997e-458e-a368-b309328f3d9e`) to write the physical
guest alias from 0 to 3. On guest return, cleanup restored 0 and verified
readback. The proxy remained alive.

XNU then reported a different undefined instruction:

```text
panic: Undefined kernel instruction: pc=0xfffffe002b8178d4 instr=d53cfc2a @sleh.c:1869
Kernel panicked very early before serial init, spinning forever...
```

This establishes progress beyond the first timer fault, not a completed
platform bootstrap. The exact next instruction is the active investigation.
