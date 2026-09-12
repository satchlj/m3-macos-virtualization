# Real-memory phase — plan (drafted 2026-09-10)

> Historical research context. Status and proposed next steps below describe the
> original investigation. See [current project status](STATUS.md) for later
> results and remaining milestones.

> **R2 status 2026-09-10 (first contact done):** Real guarded execution works end to
> end. SPTM completes full init to idle with the `TPIDR_GL2` GL2-bank shadow + A/B/C
> backing (attempt-21), and a real guarded **service call** into the dispatcher
> succeeded (attempt-23, `--first-contact`): idle→`genter #0`→dispatcher `0xa4524`→
> type-0 T0→halt at `0xa4ac0` before the C service, non-mutating; ABI confirmed live.
> **Consecutive real-guarded runs are impossible** (SPTM locks SPRR/GXF; a 2nd
> `hv_start` crashes to macOS — no EL2 fix). The sustainable path is **multiple
> guarded calls within one run** (`--guarded-call-selectors`, built and suite-green),
> letting the C service run and looping the idle→genter. Next: the service
> selector-map analysis picks a safe query selector, then attempt-24 (multi-call) on
> a fresh boot. See [real-memory-stage0/attempt-23-first-contact.md](real-memory-stage0/attempt-23-first-contact.md),
> [real-memory-stage0/multi-call-runbook.md](real-memory-stage0/multi-call-runbook.md).


> **Status update 2026-09-10 (attempt-17):** Real guarded execution is achieved.
> The EL2 SPRR/GXF context fix (enable `SPRR_CONFIG_EL1` + `GXF_CONFIG_EL1` at EL2
> before the guest runs, mirroring the vel2 HV) unblocked the EC-0 faults that
> stopped attempts 12–16. Under `--real-guarded`, the guest ran the full SPRR/MMU
> bring-up (7.786 M events) and executed a **real `genter`** — SPSR flipped into
> the guarded world (`0x600003c4 → 0x604013c5`). It then **diverted to a spin at
> physical `0x100033f1a00`** (below the guest window, in the m1n1/boot region),
> likely a guarded-world exception via `VBAR_GL1`. The frontier is now **explaining
> and clearing that divert**: attempt-18 (batched, ~6 min) plus the guarded-bank
> snapshot (added in the finalizer) will show whether `0x100033f1a00` is `VBAR_GL1`
> or a stale jump target. See
> [real-memory-stage0/attempt-17-real-genter.md](real-memory-stage0/attempt-17-real-genter.md),
> [real-memory-stage0/README.md](real-memory-stage0/README.md), and the
> attempt-18 runbook at the end of this file.

The observation phase reached its boundary: the SPTM monitor self-configures fully
and then initializes large managed structures at scattered physical addresses with
read-modify-write semantics
([sptm-self-configuration-result.md](sptm-self-configuration-result.md)). To go
further the monitor must operate against **real machine memory** rather than a
zeroed, isolated sandbox. This document plans that phase carefully and does not
authorize any hardware step on its own. Each stage below has an explicit go/no-go
gate.

## Objective

Let the monitor's structure initialization succeed on real content so we can
observe what it does *after* self-configuration, while keeping the host in
control and the installed system recoverable.

## The central tension

Every prior stage was safe because the guest was isolated and its security state
was staged, never applied. Real memory removes that isolation for the regions we
back:

- The monitor read-modify-writes real structures, so it will act on and mutate
  real machine memory. We lose the "records, never applies" guarantee for those
  regions.
- Some of what it initializes is page-ownership and protection metadata. If that
  metadata is later consulted by hardware (or by a real guarded entry), wrong or
  partial state could fault in ways that are harder to unwind than a clean HV
  exit.
- Real guarded execution (`genter` on hardware) and real SPRR enforcement change
  what instructions and permissions are live. That is the opposite of the
  observation posture and needs its own gate.

So the phase must be staged from least to most commitment, validating
reversibility at each step.

## Options, least to most commitment

- **R1 — Real backing, virtual GXF (recommended first).** Keep the virtual
  guarded world and staged registers, but map *real* physical memory into stage-2
  for the IPAs the monitor's structure pointers reach, so its RMW succeeds on real
  content. Hardware SPRR and hardware guarded entry stay off. Lowest commitment;
  answers whether real content alone advances execution.
- **R2 — Real guarded entry.** Replace virtual `genter` with a real hardware
  guarded entry so guarded instructions are defined and guarded state is real.
  Larger: real GXF, and real SPRR enforcement follows. Gated on the offline
  permission model (below).
- **R3 — Minimal virtualization.** Run the monitor close to natively with the HV
  only observing. Largest commitment; only consider after R1/R2 are understood.

## Hard prerequisites (before any R-stage hardware run)

1. **Offline SPRR permission model validated.** Standing rule: no hardware SPRR
   enable until the permission model is validated offline against the captured
   `PPERM_EL1`/`UPERM_EL0` and the monitor's leaves
   ([sprr-leaf-permissions.md](sprr-leaf-permissions.md)). R2/R3 depend on this;
   R1 does not enable SPRR but the model should still be ready.
2. **Region map determined.** Enumerate the monitor's structure pointers (the
   table at context `x9`, offsets `0x12f8`, `0x1308`, …) and the VA→IPA mapping
   for each, so R1 backs the right physical pages instead of chasing faults one at
   a time. Walk the monitor's stage-1 (the `translate` tool already exists) at the
   point of first structure access.
3. **Reversibility check defined.** Confirm chainload_preserve_boot still restores
   the installed boot after a real-memory run, and decide what real physical
   ranges are safe to hand the monitor (must not overlap the installed boot
   object, SEPFW, or anything persistent). Define the clean-exit and recovery
   path explicitly.
4. **Scope of mutation bounded.** Identify whether the monitor writes to anything
   persistent or secure (SEP, fuses, carveouts) versus ordinary DRAM it manages.
   Real backing is only acceptable for ordinary DRAM it owns.

## Staged plan with gates

**Stage 0 — offline (no hardware).**
- Build the region map (prereq 2) from the attempt-9 bundle plus a short
  diagnostic run that snapshots the monitor's stage-1 for the structure VAs.
- Validate the SPRR permission model offline (prereq 1).
- Decide the safe real-DRAM range and the recovery path (prereqs 3, 4).
- Gate: region map + permission model + safe range all in hand → proceed to R1.

**Stage R1 — real backing under virtual GXF. [effectively demonstrated 2026-09-10]**
- attempts 8/9/11 showed the backing set is just three scattered regions
  A `0x211050000:3`, B `0x211e40000:3`, C `0x211f00000:17` (D–F dormant, G/H in
  guest RAM). Backing A/B/C — even with *zeroed* frames — cleared the entire
  structure init and ran the full 16 M-step budget with no fault: SPTM completes
  initialization and parks in a WFE idle loop
  ([wake-path.md](real-memory-stage0/wake-path.md)). Clean HV exit, installed
  boot intact.
- Remaining R1 refinement (optional): a "real-frame" `--back-page` mode (allocate
  from the safe pool `0x10100000000..`, do not zero) if real content turns out to
  matter for the wake path. Not required to reach idle.
- Gate: **met** — advancement to idle, clean exit, no persistent-state mutation.

**Stage R2 — the WFE wake / guarded-call interface (the real Phase 2).**
The wake analysis pins the target concretely. SPTM idles at `wfe`; EL exceptions
are recorded-then-fatal (`VBAR` handlers all end in `mov x0,#0xDEAD; wfe`), so the
service path is **not** the EL vectors. Real work enters through GXF: a lower
level executes `genter`, landing in the guarded-call dispatcher at
`GXF_ENTRY_EL1 = 0xfffffe00070a4524`, which reads the guarded ESR
(`S3_6_C15_C10_5`) low 5 bits as a call type and dispatches five typed handlers
(0–4; anything else panics). Details in
[wake-path.md](real-memory-stage0/wake-path.md).

Exercising this needs a **real guarded entry**, which brings **real SPRR
enforcement** — so R2 must satisfy the SPRR go-conditions from
[real-memory-stage0/sprr-permission-model.md](real-memory-stage0/sprr-permission-model.md)
(enable SPRR only jointly with real `genter`, exact captured values and lock
order, coverage gap now closed by attempt-10). Staged sub-steps:

1. **[done] Enumerate the dispatch handlers (T0–T4)** —
   [call-abi.md](real-memory-stage0/call-abi.md). ABI: `genter` type 0 = call
   (selector in x16, args x0–x7, result x0 via gexit); types 1–3 guarded
   exceptions; type 4 config-bit-15 CAS. Per-selector map (incl. kernel-launch
   selector) is a deeper decode, cheaply obtainable by observing the first real
   `genter`.
2. **[done] Finalize the SPRR permission model (Wave 2)** —
   [sprr-permission-model.md](real-memory-stage0/sprr-permission-model.md). Full
   walk, 13,857 leaves, no missing tables, gap closed; six leaf classes; no W^X
   anomaly; validator raises nothing (go-condition 3 met). Enable sequence
   `0x1→0xfb→genter→0xff` with captured PPERM/UPERM/PMPRR; validate at the
   enable-point snapshot (state mutates between passes).
3a. **[resolved] real-enable mechanism** —
   [real-memory-stage0/real-enable-mechanism.md](real-memory-stage0/real-enable-mechanism.md).
   Six safe hardware iterations settled it (attempts 12–17). The final, working
   shape: (i) enable `SPRR_CONFIG_EL1` + `GXF_CONFIG_EL1` **at EL2** before the
   guest runs (the missing context — this is what unblocked everything); (ii) leave
   `SPRR_CONFIG`/`GXF_CONFIG`/`GXF_ENTRY`/`GXF_STATUS`/`TPIDR_GL*` **native**
   (untrapped) in the guest; (iii) apply the guest's perms/bank writes
   (`SPRR_PPERM_EL1`, `SPRR_UPERM_EL0`, `APCTL_EL1`, `*_GL1`) via their EL12/GL12
   aliases (`HV.MSR_REDIRECTS`); (iv) genter/gexit native. Dead ends ruled out:
   EL2 `u.msr` of the EL1 name (attempt-13, hit the HV's own copy), pure native
   perms (attempt-14, EL1 SPRR gated by EL2), EL12 aliases for CONFIG (attempts
   15–16, undefined at EL2). Open item: non-redirectable perms (PMPRR/SH) have no
   alias yet — not reached before the divert, so deferred.
3b. **[done] first real genter (attempt-17).** genter executed; SPSR entered the
   guarded world; then diverted to a spin at physical `0x100033f1a00`. See the
   status banner and [attempt-17](real-memory-stage0/attempt-17-real-genter.md).
   **Next = explain the divert** (attempt-18 runbook below), not more mechanism
   work.
3. **[drafted] genter driver design** —
   [genter-driver-design.md](real-memory-stage0/genter-driver-design.md). Real
   GXF + real SPRR + a normal-world EL1 stub that `genter`s; Option B (synthetic
   normal-world entry) for first contact, Option A (real launch) for fidelity;
   start with a non-mutating selector. Notes the observability tradeoff (staging
   stream is lost under real GXF; rely on EL2 single-step/traps).
4. **[pending] Reversibility rehearsal.** Real SPRR + real guarded state change
   enforcement and privilege; rehearse the clean-exit/recovery path and confirm
   the installed boot survives before the first real-genter run.
5. **[done] First-contact spec** —
   [first-contact-spec.md](real-memory-stage0/first-contact-spec.md). Key safety
   result: single-stepping halts at the dispatcher **before** the type-0 path
   calls the service (`0xe8d8c`), so first contact is non-mutating **by
   construction, regardless of selector** — no need to pre-pick a "safe" call.
   Normal-world context, the empirically-determined type-0 immediate, and the
   observability plan (single-step across `genter`, snapshot the GL bank/frame)
   are specified.
- Gate (before any real-genter hardware run): ABI mapped ✓ + SPRR model validated
  ✓ + genter-driver designed ✓ + first-contact spec ✓. **Build done, genter ran
  (attempt-17).** The probe's `--real-guarded` path (real-SPRR-enable + native
  GXF + EL12-aliased bank) works: the guest reached and executed a real `genter`
  from its own bring-up — no synthetic Option-B stub was needed for first contact,
  because the monitor's own early path issues the entry. The remaining work is
  **diagnostic, not build**: explain the post-genter divert to `0x100033f1a00`
  before pushing into the dispatcher. Reversibility rehearsal still stands as a
  prerequisite before any run that lets the guarded path *mutate* (attempt-17 spun
  without mutating; the dispatcher's service call at `0xe8d8c` is the mutation
  boundary per [first-contact-spec.md](real-memory-stage0/first-contact-spec.md)).

## Open questions to resolve in Stage 0

- How many structure regions are there, and how large is each? (Bounds the real
  DRAM we must supply.)
- Does the monitor expect specific *content* in these structures (e.g. a valid
  memory map it reads), or does it initialize them from scratch? RMW suggests it
  reads existing values — whose provenance we must understand.
- Where does the monitor get its notion of physical memory extent (ADT? a
  hardware register?), and can we make that consistent with the DRAM we hand it?
- What is the earliest safe abort point if a real-memory run misbehaves?

## Constraints carried forward (unchanged)

- Fresh-boot gate every power cycle; confirm one owner before any target op.
- Do not chainload after HV execution without a fresh installed boot.
- Artifacts stay local (now on analysis host over direct USB; USB host is out of the loop
  while direct). Nothing pushed to origin unless asked.

## attempt-18 runbook (staged; run when target M3 reconnects)

Goal: reach the post-`genter` divert **at speed** and capture the guarded bank so
we can decode `0x100033f1a00`. No mutation — this stops at/spins after the entry,
before the dispatcher's service call.

Config: `artifacts/runs/observe-sprr/attempt-18.config.json` — `real_guarded=true`,
`single_step_after=0` (fully batched; attempt-17's `7786000` caused the ~15-min
crawl by single-stepping 525 K post-divert steps), `stop_on_vector_entry=true`,
`steps=16777216`, `step_batch=256`, `stage_el2_config=true` (the EL2 SPRR/GXF
context enable). Virtual GXF is off by implication of `real_guarded=true` (the two
are mutually exclusive; there is no separate `virtual_gxf` key to set).

Pre-flight (each of these was a real cost at least once; check before launching):
1. **Fresh-boot gate.** Power-cycle target M3, confirm one owner, confirm the direct
   USB node (`/dev/cu.usbmodem…`) — a wedged prior run (attempt-17 was killed
   mid-USB) requires this anyway.
2. **Grep the config for slow spans** before launch: confirm `single_step_after`
   is `0` (or a bounded window), not a multi-million step value. This one check
   would have saved the attempt-17 crawl.
3. **Clear the output dir** if reusing a name (the pipeline rejects an existing
   `--output` dir — a prior rerun failed on this).

Expected: ~6 min to the divert; the finalizer's `guarded_bank_exit` snapshot
records `VBAR_GL1`, `SPSR_GL1`, `ELR_GL1`, `ESR_GL1`, `GXF_ENTRY_EL1`,
`GXF_PABENTRY_EL1` via the EL12/GL12 aliases.

Decode after the run (offline, no hardware). Two falsifiable predictions, grounded
in the vel2 source study — see
[real-memory-stage0/attempt-17-divert-analysis.md](real-memory-stage0/attempt-17-divert-analysis.md):
- **Prediction 1 — divert is a guarded sync vector:** on Apple GXF a same-EL
  guarded synchronous exception vectors to `VBAR_GL1 + 0x200` (`src/gxf_asm.S:43`,
  the `.align 7` vector table). So expect **`VBAR_GL1 == 0x100033f1800`**
  (`0x100033f1a00 − 0x200`). If so the divert is confirmed a guarded exception
  taken by the `msr S3_6_C15_C11_1, x0` at `0xb0b98`; `ESR_GL1` should name the
  faulting instruction and `ELR_GL1` ≈ `0xfffffe00070b0b98`. The vector base points
  into the physical boot region, so the slot is an effective spin — no guarded
  handler is installed under the probe's staging.
- **Prediction 2 — real genter target:** `genter` is a fixed-pointer transfer
  (not a vector) to `GXF_ENTER`/`GXF_ENTRY_EL1` (`src/gxf_asm.S:45`). Expect
  **`GXF_ENTRY_EL1 == 0xfffffe00070b0b98`**, reconciling with the virtual-phase
  dispatcher `0xa4524` (that was the virtualized model; the real fixed entry is
  `0xb0b98`).
- **If Prediction 1 fails:** `0x100033f1a00` is a stale/parked jump target — capture
  `GXF_PABENTRY_EL1` and check the console for "Guest exception not handled,
  rebooting." (the `src/start.S` reset parks).

Follow-on (only after the divert is understood, and after reversibility rehearsal
if the next step permits mutation): single-step a **bounded window** across the
`genter` (proposed `--single-step-window N:COUNT` tooling) to capture the
transition cleanly without single-stepping the spin.
