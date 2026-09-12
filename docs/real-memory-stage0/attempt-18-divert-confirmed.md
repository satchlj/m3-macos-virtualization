# attempt-18 — divert confirmed: guarded instruction-abort on unset guarded vectors (2026-09-10)

Batched `--real-guarded` run (config `attempt-18.config.json`, `single_step_after=0`,
`stage_el2_config=true`). Clean: `proxy_alive_after_exit=true`, non-mutating,
installed boot intact. Ran 659 s to the 16 M-step budget (`stop_reason
instruction-budget`).

## Both attempt-17 predictions confirmed

Exit snapshot `report['guarded_bank_exit']`:

| register | value | meaning |
|---|---|---|
| `VBAR_GL1` | `0x10003125800` | guarded vector base |
| `GXF_ENTRY_EL1` | `0xfffffe00070b0b98` | genter landing (SPTM VA) |
| `GXF_PABENTRY_EL1` | `0xfffffe00070bcaf4` | guarded abort entry (SPTM VA) |
| `ESR_GL1` | `0x86000005` | EC 0x21 instr-abort, IFSC 0x05 (translation fault L1) |
| `ELR_GL1` | `0x10003125a00` | faulting guarded PC = the vector slot |
| `SPSR_GL1` | `0x606013c5` | guarded |
| `ASPSR_GL1` | `0x3` | |

- **Prediction 1 (divert = guarded sync vector): TRUE.** `VBAR_GL1 + 0x200 =
  0x10003125800 + 0x200 = 0x10003125a00`, exactly the spin address. The divert is
  the same-EL guarded synchronous exception vector slot, as the vel2 source
  predicted (`src/gxf_asm.S:43`, `.align 7` table, `+0x200` sync).
- **Prediction 2 (real genter target): TRUE.** `GXF_ENTRY_EL1 =
  0xfffffe00070b0b98`, exactly the genter landing from the trace. The
  virtual-phase dispatcher `0xa4524` was a model-only artifact; the real fixed GXF
  entry is `0xb0b98`.

The spin address differed from attempt-17 (`0x100033f1a00` → `0x10003125a00`)
because `VBAR_GL1` is a **run-relocated physical** address (m1n1's own guarded
vectors, whose physical load base shifts per run); the page-offset `0x800` + `0x200`
sync slot = `0xa00` is stable across both runs.

## What actually blocks execution

The terminal spin is a **self-sustaining guarded instruction abort**: `ESR_GL1` EC
`0x21` (instruction abort, same EL), IFSC `0x05` (translation fault, level 1), with
`ELR_GL1` equal to the vector slot itself (`0x10003125a00`). So the guarded vector
slot at `VBAR_GL1 + 0x200` is **not mapped executable in the guarded translation
regime**: the vector fetch faults, re-vectors to the same slot, and loops.

Why the vectors are invalid: SPTM set its GXF **entry** and **abort** pointers
(`GXF_ENTRY_EL1`, `GXF_PABENTRY_EL1`, both SPTM VAs) but `VBAR_GL1` still holds
**m1n1's** guarded vectors at a run-varying physical address (`0x10003125800`).
SPTM had **not installed its own guarded exception vectors** when the first guarded
fault occurred — the first guarded instruction after `genter` faulted before SPTM
reached its `VBAR_GL1` setup.

## Open: the original trigger syndrome (needs a bounded single-step)

`ESR_GL1`/`ELR_GL1` at exit describe the *self-fault* of the vector slot after 16 M
spin events, **not** the original fault that started it. attempt-17's single-step
showed the trigger at `msr S3_6_C15_C11_1, x0` (`0xb0b98`), but its guarded syndrome
was overwritten by the spin. To learn *why* that first guarded instruction faults
(translation → back a page; permission → apply a perm; undefined → different
approach), single-step a **bounded window** around the genter (index ≈ 7,786,860)
and capture `ESR_GL1`/`ELR_GL1`/`FAR_GL1` at the **first** guarded fault, before the
spin overwrites them. This justifies building `--single-step-window` (previously
deferred as speculative — now data-driven).

## Config lesson (banked)

`stop_on_vector_entry` watches the EL1 vector, so it **missed** this guarded
(`VBAR_GL1`) vector; the batched run spun to the 16 M budget (659 s, ~9 M spin
events). A real-guarded run needs a **guarded-vector / guarded-abort stop
condition** to halt at the divert instead of tracing the spin.

## Next steps

1. **Build (offline): DONE.** `--single-step-window START:COUNT` (single-step a
   bounded window, batch elsewhere) and `--stop-on-guarded-vector` (a second
   `GuestExceptionStop` driven by `VBAR_GL1`, snapshotting the guarded bank at the
   first divert) are implemented in `sptm_entry_probe.py`, wired through the
   pipeline (fields + validation + lint), and covered by tests (suite green).
   The lint now also flags a real-guarded run lacking a guarded-vector stop (the
   spin-to-budget footgun this run hit).
2. **Targeted run: STAGED as attempt-19** (`attempt-19.config.json`/`.sh`,
   lint-clean): `single_step_window = 7780000:20000` (brackets the genter at index
   ≈7,786,860 with margin) + `stop_on_guarded_vector = true`. It batches to the
   window, single-steps across the genter, and halts at the first divert with the
   guarded bank captured at **zero overshoot** — so `ESR_GL1`/`ELR_GL1` hold the
   *original* trigger (the `msr S3_6_C15_C11_1` fault), not the self-fault. ~6 min,
   non-mutating (before the dispatcher service call at `0xe8d8c`).
3. **E2 fork (user's call):** given the trigger cause from attempt-19, either back
   the pages/permissions SPTM's guarded bring-up needs so it installs its own
   `VBAR_GL1` and proceeds, or install a minimal observable guarded vector. The
   genter mechanism itself is not the blocker — it works.
