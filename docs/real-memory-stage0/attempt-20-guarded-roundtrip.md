# attempt-20 — GL2 shadow works: first complete guarded round-trip (2026-09-10)

With `TPIDR_GL2` moved out of `real_native` into the apple_shadow set (one-line
probe fix, no firmware rebuild), SPTM's first guarded instruction no longer faults.
Config: same as attempt-19 (`single_step_window 7780000:20000`,
`stop_on_guarded_vector`, `real_guarded`). Clean, non-mutating.

## Result: the fix worked, SPTM advanced

- **No guarded divert** (`guarded_vector_stop: none`). The `TPIDR_GL2` shadow let
  SPTM's guarded per-CPU init proceed.
- **Exactly one complete genter→gexit round-trip:** normal→guarded at index
  7,786,860 (entry `GXF_ENTRY_EL1 = 0xfffffe00070b0b98`), guarded→normal at
  7,786,882. So the guarded episode is a brief ~22-instruction per-CPU init
  (set `TPIDR_GL2` + a few guarded registers), then `gexit`. This is the first
  time real guarded execution completed and returned under the probe.
- SPTM then ran ~21,300 more **normal-world** instructions (to index 7,808,220)
  before stopping.

## New frontier: a normal-world data abort

Stop: `stop_reason = unsupported-exception` at `pc 0xfffffe00070bf690` (SPTM text,
normal world, SPSR `0x2013c4` = EL1h, guarded bit clear).

```
ESR  0x93c98005  -> EC 0x24 (data abort, lower EL), DFSC 0x05 (translation fault L1), WnR=0 (read), ISV=1
FAR  0xfffffe0038020218   (a high SPTM VA; x1/x2/x3 ~0xfffffe0007123exx point at SPTM data)
```

SPTM, back in the normal world, reads `0xfffffe0038020218` and the access
translation-faults. This is **distinct** from the observation-phase structure-init
faults (those were physical IPAs `0x211xxx` handled by stage-2 backing): this is a
fault on a high VA the guest reaches at EL1.

## Open question for the next step

Decide whether this is:
- a **stage-2** fault (SPTM's stage-1 maps the VA to an IPA that our HV stage-2
  doesn't back) → tractable with `--back-page` once the IPA is known (need
  `HPFAR_EL2`); analogous to the R1 structure backing; or
- a **stage-1** fault (SPTM's own page tables, as built under the probe, don't map
  the VA) → means SPTM expects a mapping its bring-up didn't establish here.

`S1PTW=0` in the ISS says the fault is on the access, not on a stage-1 page-table
walk. Next: capture `HPFAR_EL2` at this stop (the IPA) and check whether the VA is
covered by SPTM's current tables (walk stage-1 with the `translate`/`snapshot-leaf`
tooling). That decides back-the-page vs. a deeper stage-1 gap.

## What is now proven

- The `TPIDR_GL2` = `S3_6_C15_C11_1` diagnosis and the trap-and-shadow fix are
  correct: SPTM's guarded per-CPU init completes and `gexit`s.
- Real guarded execution works end to end under the probe (enter, run, exit).
- The blocker moved from "undefined guarded register" to "a normal-world memory
  access needing backing/mapping" — back in familiar observation-phase territory,
  but now on the far side of the guarded round-trip.
