# SPTM guarded per-CPU init sequence (from attempt-20, 2026-09-10)

First characterization of real guarded execution: the ~22-instruction guarded
episode SPTM runs per CPU, captured single-stepped in attempt-20 (indices
7,786,859–7,786,882, one genter→gexit round-trip).

## The sequence

| idx | pc (VA) | action |
|----:|---------|--------|
| 7786859 | `0xfffffe00070b0c20` | `genter` (normal world) |
| 7786860 | `0xfffffe00070b0b98` | lands at `GXF_ENTER` (guarded world; SPSR guarded bit set) |
| 7786861 | `0xfffffe00070b0b9c` | **write `TPIDR_GL2`** — guarded per-CPU base *(the instruction that faulted UNDEF pre-fix)* |
| 7786866 | `0xfffffe00070b0bb0` | **write `SPRR_PPERM_EL1`** — guarded permissions (applied via EL12 redirect) |
| 7786880 | `0xfffffe00070b0be8` | **write `VBAR_GL1`** — guarded exception vector base |
| 7786882 | `0xfffffe00070b0bf0` | `gexit` back to normal world (SPSR guarded bit clear) |

(The intervening `instruction-step` events are ordinary register/stack setup between
these three system-register writes.)

## Why this explains the whole divert saga

SPTM sets `VBAR_GL1` (its guarded vectors) at `0xb0be8`, which is **after** the
`TPIDR_GL2` write at `0xb0b9c`. In attempts 17–19, `TPIDR_GL2` trapped UNDEF at the
very first guarded instruction (`0xb0b98`/`0xb0b9c`) — *before* SPTM ever reached
`0xb0be8` to install its own guarded vectors. So the resulting undefined-instruction
exception vectored through the still-unset (m1n1's, run-relocated) `VBAR_GL1` into an
unmapped boot-region slot → the self-fault spin.

Shadowing `TPIDR_GL2` (attempt-20) lets SPTM proceed past `0xb0b9c`, set its
permissions and **its own `VBAR_GL1`**, and `gexit` cleanly. The per-CPU guarded init
completes. That is the mechanism, end to end.

## Notes / caveats for later

- **`VBAR_GL1` is shadowed, not applied to hardware.** SPTM's write is stored in the
  probe's apple_shadow (read-back coherent) but the hardware guarded vector base is
  not set to SPTM's value. It did not matter here because the per-CPU init took no
  guarded exception. But if SPTM later re-enters the guarded world and *faults*, the
  hardware would still vector through m1n1's `VBAR_GL1`, not SPTM's — a potential
  future divert. If that happens, `VBAR_GL1` may need real application (like
  `SPRR_PPERM` via a redirect/alias) rather than pure shadowing.
- **`SPRR_PPERM_EL1` is really applied** (EL12 redirect), so SPTM's guarded
  permission intent reaches the guest EL1 SPRR bank.
- The init is short and self-contained: one genter, three guarded system-register
  writes, one gexit. Real guarded execution works; the frontier moved to normal-world
  memory backing (see [attempt-20-guarded-roundtrip.md](attempt-20-guarded-roundtrip.md)).
