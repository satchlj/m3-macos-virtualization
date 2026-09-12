# SPTM self-configuration under observation — result (2026-09-10)

This is the milestone result of the observation phase: an end-to-end trace of what
the M3 (target M3) SPTM monitor does from entry through complete self-configuration,
observed without enforcing or faking its security state, up to the point where it
depends on real machine memory. It consolidates attempts 4–9. Detailed
per-attempt raw logs are retained outside Git;
mechanism docs are cross-referenced below.

## Goal and method

Observe the monitor's own behaviour after it takes control, rather than reproduce
upstream's shadow machinery. The host runs the m1n1 vel2 fork at virtual EL2; the
`stopped()` callback rewrites the monitor's privileged instructions to HVC and
**stages** them — records the write, returns a shadow on read — so the monitor
advances believing its configuration took effect while hardware state is left
untouched. Tooling built for this:

- Virtual guarded world ([virtual-guarded-world.md](virtual-guarded-world.md)):
  models `genter`/`gexit`, the GL1 exception bank swap, SP swap and status flag,
  with no permission or guarded-page enforcement.
- SPRR observation ([sprr-observation.md](sprr-observation.md)) and offline leaf
  decode ([sprr-leaf-permissions.md](sprr-leaf-permissions.md)).
- Live TTBR-switch validation ([live-ttbr-switches.md](live-ttbr-switches.md)).
- `--back-page IPA[:COUNT]` to back guest IPA pages with zeroed host RAM;
  `--snapshot-leaf` to walk and decode a final leaf; `--single-step-after` to
  capture a vector-entry syndrome with zero batch overshoot.
- Pipeline, catalog and offline trace tools ([probe-pipeline.md](probe-pipeline.md),
  [trace-events-summary.md](trace-events-summary.md),
  [trace-disassembly.md](trace-disassembly.md)).

Throughout, `sprr_observation.enforced = false`: hardware SPRR is never actually
enabled. The monitor believes it is running under a locked permission regime that
the host only records.

## What the monitor does, in order

Captured as one coherent sequence around trace indices 7.78M–7.81M (the tight
configuration block spans ~60 steps):

1. **MMU bring-up and page-table rebuild.** Enables its VHE MMU under a validated
   profile, then performs two live TTBR switches; the second installs a
   13,834-leaf kernel map (`complete_candidate_root`).
2. **SPRR bring-up.** `SPRR_CONFIG ← 1` (enable); populates `SPRR_UPERM_EL0`,
   `SPRR_PMPRR_EL1`, `SPRR_PPERM_EL1`; `SPRR_CONFIG ← 0xfb` (enable + lock_config
   + lock_perm + lock_kernel_perm).
3. **Guarded world.** `GXF_CONFIG ← 1`, sets `GXF_PABENTRY`/`GXF_ENTRY`, executes
   `genter` into guarded execution, sets `TPIDR_GL2`, then rewrites
   `SPRR_PPERM_EL1` and `SPRR_CONFIG ← 0xff` from inside guarded mode.
4. **Register family.** Stages a family of EL2 / Apple / guarded registers: the
   op1=4 `C15_*` set, op1=6 guarded (`GXF_*`, `ASPSR_EL1`), the timer
   `AGTCNTRDIR_EL12`, and `PMCR1_GL1` (op1=1, added after attempt-7).
5. **Runtime structure initialization.** Reads a table of pointers from its
   context and begins read-modify-write initialization of multiple large managed
   structures (page-ownership metadata / per-region descriptors). This is where
   observation ends — see the boundary below.

## Two corrections worth preserving

- **No SPRR read-divergence at the faulting page.** attempt-6 suggested the
  monitor's exception handler permission-faulted reading data embedded in its own
  executable segment because SPRR was off. attempt-7 disproved this: the leaf for
  `0xfffffe00070ac000` grants kernel read under native, ordinary-SPRR and
  guarded-SPRR alike (only *execute* differs by world). The batched syndrome that
  looked like a permission fault was a post-loop artifact. Lesson recorded in
  memory: capture the clean single-stepped first-entry syndrome before
  interpreting a stop.
- **The real trigger was an undefined guarded instruction.** The clean syndrome
  (`ESR_EL12 = 0x2000000`, EC 0, `FAR 0`) was an undefined-instruction exception
  on `msr PMCR1_GL1` — a guarded register undefined outside a *real* guarded
  entry, because GXF was only virtualized. Staging it (attempt-8) advanced
  execution, confirming the divergence was guarded-world state, not SPRR
  permissions.

## The boundary

After the register family is staged, the monitor initializes large runtime
structures through context pointers:

- region A: VA `0xfffffe0038020000` → IPA `0x211050000`
- region B: VA `0xfffffe0038070000` → IPA `0x211e40000`

The VA bases are ~320 KB apart but their backing IPAs are ~14.6 MB apart, so the
physical pages are **scattered**; a contiguous IPA range cannot cover them. The
accesses are **read-modify-write** (OR a flag into an existing value), so a zeroed
sandbox both cannot be extended to reach them and cannot supply the content the
monitor expects. This is the shape of SPTM initializing machine-wide managed
metadata, which requires the real machine memory map.

**Conclusion.** Pure observation has reached its natural end. The monitor fully
self-configures (MMU rebuild, SPRR tables + triple lock, guarded entry, register
family, timer) and then depends on real machine memory. Going further requires
supplying that memory — the real-memory phase
([real-memory-phase-plan.md](real-memory-phase-plan.md)).

## Artifacts

Attempts 4–9 are imported and catalogued under experiment `sprr-observation-v1`.
Trace bundles and reports live under `artifacts/runs/` on analysis host (gitignored). The
probe, pipeline and offline tools are on `main`; the suite is green (325 tests).
Fresh-boot gate and one-owner discipline were observed for every hardware run.
