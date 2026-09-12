# attempt-19 — the divert trigger: SPTM's first guarded msr is undefined (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Ran with the new `--single-step-window 7780000:20000` + `--stop-on-guarded-vector`.
The run batched to the window, single-stepped across the genter, and **stopped at
the first divert with zero overshoot** — capturing the *original* trigger syndrome
before the vector slot's self-fault could overwrite it (the gap attempt-18 left).

Operational note: this run followed its **own** fresh gate. attempt-19's first
launch reused attempt-18's spent chainload and rebooted target M3 at `hv_start`
(`[Errno 6] Device not configured`); the installed boot auto-restored. Each
real-guarded run needs a fresh chainload — see the playbook and memory.

## The capture (clean, zero overshoot)

```
stop_reason        : guarded-vector-entry
trace_index        : 7786637   (recorded_events_after_hit = 0)
VBAR_GL1           : 0x100033b9800
divert event pc    : 0x100033b9a00   (= VBAR_GL1 + 0x200, guarded sync vector)
ELR_GL1            : 0xfffffe00070b0b98   (the faulting PC)
ESR_GL1            : 0x02000000
GXF_ENTRY_EL1      : 0xfffffe00070b0b98
GXF_PABENTRY_EL1   : 0xfffffe00070bcaf4
```

## Diagnosis

`ESR_GL1 = 0x02000000` decodes to **EC 0x00 (undefined instruction), IL=1,
ISS=0**, and `ELR_GL1` points exactly at `0xfffffe00070b0b98` — the
`msr S3_6_C15_C11_1, x0` instruction. So SPTM's **first guarded instruction is an
undefined instruction** in the guarded world as we have configured it.

The EC is the discriminator among the three hypotheses from attempt-18:
- **not** a translation fault (would be EC 0x21, IFSC 0x05) — so not "back a page";
- **not** a permission/config trap (would be EC 0x18) — so not "apply a permission"
  and not a defined-but-trapped register;
- **it is** EC 0x00 = the register `S3_6_C15_C11_1` (op0=3, op1=6, CRn=15, CRm=11,
  op2=1) is **not implemented/enabled** in our guarded context. Executing the `msr`
  raises undefined-instruction, which vectors through `VBAR_GL1 + 0x200` into the
  (unmapped, run-relocated) boot-region slot → the self-fault spin.

This matches the source study (the register appears nowhere in the vel2 tree) and
now confirms on hardware that it is also undefined on the CPU as we configure the
guarded world. It is an SPTM-specific guarded per-CPU register whose enable we have
not reproduced.

## The E2 fork (what to decide next)

The blocker is neither backing nor permission — it is that our virtualized guarded
world does not make `S3_6_C15_C11_1` defined. Options, to decide once the register
is identified (research in progress):

1. **Enable it.** Find and set whatever gates the `S3_6_C15_C11_x` space (a GXF/SPRR
   config or Apple IMP-DEF access enable) at EL2 before `genter`, so the `msr`
   executes natively as it does on real SPTM. Highest fidelity.
2. **Trap-and-shadow it.** Add `S3_6_C15_C11_1` to the HV's guarded emulation set
   (like the other guarded registers via redirects/shadow) so the write is handled
   at EL2 instead of trapping undefined. Lower commitment, keeps momentum, but only
   sound once we know the register's semantics (pass vs shadow).
3. **It may be M3-specific / core-type-specific.** m1n1's register tables are
   M1/M2-era; the register may exist only on t8122 or only on P-cores. Confirm
   before choosing 1 vs 2.

Research task (offline) is running to identify `s3_6_c15_c11_1` and its enable.

## Register identified: `S3_6_C15_C11_1` = `TPIDR_GL2` (research complete)

`s3_6_c15_c11_1` (op0=3, op1=6, CRn=15, CRm=11, op2=1) is **`TPIDR_GL2`** — the
guarded-EL2 (GL2) per-CPU thread-ID (base) register. Confirmed in m1n1's own table
(`local/m1n1-vel2/proxyclient/m1n1/apple_regs.json:268`); the `[3,6,15,11,x]` block
is the full GL2 bank (`VBAR_GL2/SPSR_GL2/ASPSR_GL2/ESR_GL2/ELR_GL2/FAR_GL2`), the
lateral sibling of the GL1 bank at `[3,6,15,10,x]`. Our own prior notes already
named it (`docs/sprr-observation.md:33`:
real HW reads `TPIDR_GL2` 248×). So SPTM's first guarded instruction is simply it
installing its per-CPU base right after `genter`.

**Why it is UNDEF under us:** the vel2 fork models the **GL1** guarded bank only
(`enum hv_vreg`/`struct hv_sprr_cpu` in `src/hv_sprr.h`, and `HV_VREGS` in
`proxyclient/m1n1/hv/sprr.py` — zero GL2 entries), and the guest physically runs at
**EL1** (virtual EL2 via VHE `*_EL12` aliases). The patcher rewrites only GL1/EL1
MSR/MRS to HVC, so `msr TPIDR_GL2` (CRm=11) is left native; a native GL2 access from
EL1 is architecturally UNDEF → EC 0x00, exactly our syndrome. There is **no
per-register enable bit** — the whole `s3_6_c15_c11_x` space is gated only by "GXF
enabled + at EL2/GL2." (Note `src/hv_vel2.c:20-22` currently forbids combining
virtual-EL2 with an active guarded world — a longer-term merge.)

**E2 fork resolved toward option 2 (trap-and-shadow):** add the GL2 bank
(`TPIDR_GL2` first, then `VBAR_GL2/SPSR_GL2/ASPSR_GL2/ESR_GL2/ELR_GL2/FAR_GL2/
AFSR1_GL2`) to `enum hv_vreg` + `HV_VREGS` (index-synced) + `struct hv_sprr_cpu` +
`hv_sprr_handle_msr`, mirroring the existing GL1 shadow. `TPIDR_GL2` is a plain
per-CPU scratch pointer, so shadowing it is semantically trivial and low-risk. The
patcher then rewrites the `msr` to an emulated HVC that stores to `cpu->tpidr_gl2`
instead of faulting, advancing SPTM past `0xb0b98` to its next guarded register
(real-HW order predicts `AFSR1_GL2`/`VBAR_GL12`/`SPRR_CONFIG` next). This is a
probe-sized change; running the monitor at real EL2/GL2 is the larger alternative.
Confirmation: after adding `TPIDR_GL2` and re-patching, single-step should advance
past `0xb0b98`; if the same UNDEF persists there, the text at `0xb0b98` was executed
from a region the patcher never covered (a different diagnostic).

## Reboot incident and corrected rule

A direct proxy `P_REBOOT` without first clearing the PMU panic breadcrumb caused
iBoot to demote the selected boot object and return to recovery/macOS instead of
m1n1. Never call `p.reboot()` directly. The guarded helper now follows upstream's
ordering by calling `PMU(u).reset_panic_counter()` first; see
[guarded target reboot](../reboot-helper-design.md). It still requires owner
authorization and local recovery access.

## What is now proven

- genter works (again): `GXF_ENTRY_EL1 = 0xb0b98`, real world switch. Three runs,
  three run-relocated `VBAR_GL1` values, each with the divert at `+0x200`.
- The divert is fully explained end to end: undefined `msr` → guarded sync vector →
  unmapped slot → spin.
- The new probe tooling (`--single-step-window`, `--stop-on-guarded-vector`)
  captured the clean trigger in one run, as designed.
