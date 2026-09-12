# Stage-0 offline SPRR permission model

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Scope: **offline, read-only** validation of the Apple SPRR permission model
against the captured monitor tables and permission registers, in service of the
standing rule that **no hardware SPRR enable happens until the permission model
validates offline** (real-memory-phase-plan.md, prereq 1; sprr-leaf-permissions.md).
No hardware, USB/serial, probe, or pipeline command was run to produce this;
every result carries `hardware_validated: false`. Nibble meanings are the public
upstream model (`hv_sprr.c`), not independently M3-validated.

## Inputs (captured)

- Final locked registers (attempt-7 leaf snapshot, config `0xff`):
  `SPRR_PPERM_EL1 = 0x2020a52a302abae6`, `SPRR_UPERM_EL0 = 0x2010002030100000`,
  `SPRR_PMPRR_EL1 = 0x40010`. `sprr_observation.enforced = false` — hardware SPRR
  was never enabled; these values were staged/recorded, not applied.
- Monitor MMU profile (`final_leaf_controls`): `ttbr0 = 0x10015064000`,
  `ttbr1 = 0x10015060000`, `tcr = 0x10800236511a511` (= `MONITOR_TCR`),
  `mair = 0x0c0804ff00bb44ff` (= `MONITOR_MAIR`). Supported 47-bit VHE profile.
- Captured table pages (attempt-7 bundle `tables/`, sha256-verified in
  `diagnostics.json`): `0x10015060000` (ttbr1 root), `0x10015064000` (ttbr0
  root), `0x10015068000`, `0x1001506c000`.
- Enable/lock sequence (identical in observe-sprr/attempt-9 and the attempt-7
  import `sprr_observation.events`):

  | trace idx | SPRR_CONFIG | PPERM_EL1 | UPERM_EL0 | PMPRR |
  |-----------|-------------|-----------|-----------|-------|
  | 7786815 | `0x1` enable | `0x2020a52a302abaf5` | `0x0` | `0x0` |
  | 7786840 | `0xfb` enable+lock_config+lock_perm+lock_kernel_perm (unk 0xc8) | `0x2020a52a302abaf5` | `0x2010002030100000` | `0x40010` |
  | 7786871 | `0xff` (unk 0xcc) | `0x2020a52a302abae6` | `0x2010002030100000` | `0x40010` |

## The model

A stage-1 leaf's `AP[2:1]` (bits 7,6), `UXN` (54), `PXN` (53) form a 4-bit index
(index bit0=PXN, bit1=UXN, bit2=AP_EL0, bit3=AP_RO). The effective kernel RWX is
`world_table[(PPERM >> index*4) & 0xf]`; user RWX is the same over `UPERM`.
`world_table` is `EL` (ordinary world) or `GL` (guarded world), with R=4,W=2,X=1:

```
EL = 0, RX, R, RW, 0, RX, R, 0, 0, X, R, RW, 0, RX, R, RW   (index 0..15)
GL = 0,  0, 0,  0, RX,RX,RX,RX, R, R, R,  R, RW,RW,RW,RW
```

### Only two indices occur in the monitor's own tables

All 139 reachable leaves are kernel-only (no leaf sets `AP_EL0`; no leaf sets
`AP_RO`/bit7 — every leaf is natively writable), so only two indices appear:

- **index 0 — `__TEXT_EXEC` (PXN clear).** VA `0xfffffe00070a0000`..`0x70fc000`
  (includes the captured leaf `0x70ac000`, desc `0x40100150ac603`, and
  `VBAR_EL12 = 0x70ad000` with its embedded data pointer `0x70ae018`).
  - PPERM nibble = `0x6`; UPERM nibble = `0x0`.
- **index 1 — data (PXN set).** VA `0xfffffe0006f00000`..`0x709c000` and
  `0x7100000`..`0x7128000` (desc pattern `…603` with bit53 set).
  - PPERM nibble = `0xe`; UPERM nibble = `0x0`.

Decoded effective kernel permissions under the **final** registers:

| leaf class | native (SPRR-off) | ordinary world (EL) | guarded world (GL) |
|------------|-------------------|---------------------|--------------------|
| index 0 (text) | **R W X** | **R** (nibble 6 → `EL[6]=R`) | **R X** (`GL[6]=RX`) |
| index 1 (data) | **R W** | **R** (nibble 14 → `EL[14]=R`) | **R W** (`GL[14]=RW`) |

User access is `-` everywhere (both UPERM nibbles are 0 → `EL[0]=GL[0]=0`). All
16 index pairs remain exactly representable by an ordinary leaf.

## Native vs SPRR divergence (the load-bearing result)

**Every one of the 139 reachable leaves diverges** between the SPRR-off native
reading and at least one SPRR world. The pattern is uniform, not incidental:

- **Read is granted in all three interpretations, for every leaf.** This
  confirms the attempt-7 correction: the exception handler's data read of
  `0x70ae018` did **not** permission-fault for lack of read permission. The
  attempt-7 stop was an undefined guarded-register write (`ESR 0x2000000`,
  EC 0, at `msr S3_1_C15_C8_2`) because GXF was only virtualized — a
  guarded-state blocker, not an SPRR-permission one.
- **Ordinary world collapses everything to read-only.** With the *final* PPERM,
  both index 0 and index 1 map to kernel R only. If hardware SPRR were enabled
  while the CPU is in the ordinary (non-guarded) world, the monitor's own text
  would be non-executable and its data non-writable → immediate instruction-fetch
  and store faults on its first step.
- **Only the guarded world is self-consistent for the monitor.** In GL the text
  is R X and data is R W — a clean W^X monitor (text not writable, data not
  executable). This is the world the monitor enters via `genter`, and it is the
  only interpretation under which the monitor's captured leaves let its own code
  run and its own data mutate.
- **Native over-grants** relative to SPRR: native gives text RWX (vs guarded RX —
  native adds W to code, breaking W^X) and data RW (matches guarded). The
  monitor deliberately relies on SPRR to *remove* the native write-on-text.

### The enable→genter→lock hardening is visible in the data

The staged sequence tightens the ordinary-world view exactly at guarded entry:

- Pre-genter PPERM `0x…baf5`: index 0 nibble `0x5` → ordinary text = **R X**;
  index 1 nibble `0xf` → ordinary data = **R W**. Bring-up code is executable and
  writable in the ordinary world.
- Post-genter rewrite to `0x…bae6` (then `CONFIG 0xff` locks it): index 0
  nibble `0x6` → ordinary text = **R**; index 1 nibble `0xe` → ordinary data =
  **R**. After it is guarded, the monitor clamps the ordinary-world view of its
  own memory to read-only, so only guarded execution can execute its text or
  write its data. This is intentional privilege separation, and it is why an
  ordinary-world SPRR run cannot work.

### Hierarchical restriction gap

Three L2 table descriptors set **PXNTable** (`0x800010017898003`,
`0x80001001789c003`, `0x8000100178a0003`, at L2 indices 26–28) pointing at
tables `0x10017898000`/`0x1001789c000`/`0x100178a0000`. Those L3 pages were
**not** retained by the diagnostic's 30-pointer walk (missing from the bundle),
so their leaves are not among the 139 decoded. Upstream ignores hierarchical
attributes under SPRR; our `guest_pt.sprr_continuation` **fails closed** on any
detected table restriction. These PXNTable sub-hierarchies are therefore
currently un-validatable offline and must be captured before they are relied on.

## Go-conditions for hardware SPRR enable (R2)

Before any hardware SPRR enable in the real-memory R2 stage, all must hold:

1. **SPRR is enabled only together with real guarded entry.** Hardware SPRR must
   never be turned on while the monitor runs in the ordinary world — its final
   PPERM makes text non-executable and data non-writable there. SPRR enable is
   coupled to R2 (real `genter`/real GXF), never to R1. Corollary: the attempt-7
   blocker (undefined guarded-register write under virtual GXF) must be resolved
   first — real guarded state is a prerequisite for, and must precede, SPRR
   enforcement.
2. **Guarded-world continuation is proven for every executing leaf.** For each
   leaf the monitor executes/writes after genter, the GL-world decode must grant
   the needed permission: text = R X (guarded), data = R W (guarded), read
   everywhere. This holds for all 139 captured leaves; it must be re-decoded
   against the *actual* final `ttbr1` in force at the enable point.
3. **Full leaf coverage — no missing tables, no unresolved hierarchical bits.**
   Capture the L3 pages behind the three PXNTable L2 entries (and any other
   `missing tables` reported by the walk) and decode them. Any leaf whose
   effective pair is not natively representable, or that sits under a
   hierarchical restriction whose SPRR meaning is unknown, is a no-go until
   resolved — the validator already refuses these.
4. **No leaf grants unexpected user (EL0) access under SPRR.** Confirmed here:
   `UPERM` nibbles for both occurring indices are 0 (no user R/W/X). Re-verify on
   the enable-point table; any user-accessible monitor leaf is a no-go.
5. **PAN posture consistent.** The observed fault path ran EL1h with PAN set
   (`SPSR 0x…13c5`). Since no monitor leaf is user-accessible, PAN does not
   remove any needed access here, but the continuation stack/text must be
   re-checked under PAN at the real enable point.
6. **Register provenance locked.** Enable only with the exact captured
   `PPERM=0x2020a52a302abae6` / `UPERM=0x2010002030100000` / `PMPRR=0x40010` and
   the `0x1 → 0xfb → 0xff` config/lock order observed; any divergence invalidates
   this offline model and re-gates.

## Wave 2 — gap closed (attempt-10, 2026-09-10)

The three PXNTable L3 sub-hierarchies flagged above were captured by an
`--snapshot-leaf` pass and walked offline. Source (read-only):
`artifacts/runs/observe-sprr/attempt-10/runs/806f120b-…/inputs/` (the `ttbr-*`
full-walk pages plus the `leaf-<VA>-<PA>` snapshot pages) and
`attempt-10/report.json`. This boot's roots (`final_leaf_controls`):
`ttbr0 = 0x10017064000`, `ttbr1 = 0x10017060000`, same `tcr`/`mair` monitor
profile. Registers unchanged: `PPERM = 0x2020a52a302abae6`,
`UPERM = 0x2010002030100000`, `enforced = false`. A full recursive walk of both
roots now reports **missing tables: NONE** and resolves **13,857 leaves**.

### Finalized leaf permission classes (whole monitor address space)

| index | descriptor bits | native K / U | ordinary K / U | guarded K / U | count | role |
|-------|-----------------|--------------|----------------|---------------|-------|------|
| 0 | exec (PXN=0) | RWX / – | R / – | **RX** / – | 24 | `__TEXT_EXEC` monitor code (incl. `0x70ac000`, VBAR) |
| 1 | data (PXN=1) | RW / – | R / – | **RW** / – | 4279 | monitor + managed data (incl. gap #3, IPA `0x211…`) |
| 3 | PXN+UXN | RW / – | **RW** / – | **R** / – | 9522 | structures writable by ordinary EL1, read-only to guarded |
| 4 | AP_EL0 | RWX / **RWX** | R / – | R / – | 27 | native-user-exec pages, fully clamped by SPRR |
| 8 | AP_RO | RX / – | R / – | R / – | 3 | native-exec, non-exec under SPRR |
| 10 | UXN+AP_RO | RX / – | **RX** / – | **RX** / – | 2 | executable in **all** worlds (`0x2bfb0000`–`0x2bfb4000`; gateway/trampoline) |

Read is granted in every interpretation for every leaf (unchanged). **Guarded W^X
holds with zero exceptions**: no leaf is both writable and executable in the
guarded world (executable classes 0 and 10 are read-only). The only
ordinary-world-executable pages are the 2 index-10 gateway leaves.

### The three gap sub-hierarchies

- **gap #1 (VA `0xfffffe0034000000`, L2[26]) and gap #2 (VA `0xfffffe0036000000`,
  L2[27]) are currently empty** — 0 valid descriptors in every captured version;
  the report's own `final_leaf_snapshots` mark their bases "Unmapped address."
  Reserved sub-tables, not yet populated.
- **gap #3 (VA `0xfffffe0038000000`, L2[28]) is sparsely populated** with 23
  `index 1` (PXN data) leaves mapping IPA `0x211050000` and
  `0x211e40000`–`0x211f40000` — the monitor's **managed-structure DRAM region**
  (the same IPA family as the attempt-5/6 fault at `0x211050218` and the
  `--back-page 0x211050000`). These fit the W^X model exactly: kernel RW in the
  guarded world, R in the ordinary world, never executable. Confirmed against the
  report's `final_leaf_snapshots` (VAs `0x38020000`/`0x3802c000`/`0x38070000`,
  idx 1, ord R / grd RW).

### sprr_continuation does NOT fail closed on the captured hierarchical bits

Every populated leaf under the PXNTable sub-tables **sets its own PXN bit** in the
leaf descriptor, so `guest_pt.translate`'s hierarchy-propagated `pxn` equals the
leaf-only reading `leaf_permissions(...)['native']` uses. Across all 13,857
leaves there are **0 hierarchy-vs-leaf mismatches**, so
`guest_pt.sprr_continuation` raises no "hierarchical table restriction has unknown
SPRR semantics" error: the PXNTable is redundant with the leaves it covers. **This
closes go-condition 3 for the captured state.** Caveat: gap #1/#2 are empty; if
they later populate with leaves that rely on the parent PXNTable *without* setting
their own PXN bit, the validator would then fail closed — they must be re-decoded
once populated.

### Live mutation observed (bounds "the leaf set that must validate")

The gap #3 table (`0x100198a0000`) and one other page (`0x1001988c000`) differ
between the `ttbr-*` full-walk pass (0 and 2048 valid descriptors) and the
`leaf-*` snapshot pass (23 and 2021) — the monitor is actively RMW-populating its
structure page tables *during the run*. Consequence: the validating leaf set is
time-dependent; go-condition 2/3 validation must be run against the exact
enable-point snapshot, not an earlier or later pass.

### Surprises beyond attempt-7's two classes

- **index 3 (9522 leaves, the bulk of the space): inverted asymmetry** — ordinary
  world RW but guarded world R. These structures are writable by the ordinary
  (OS/EL1) world yet read-only to the guarded monitor itself.
- **index 4 (27 leaves): the widest native/SPRR gap** — native grants kernel RWX
  *and* user RWX; SPRR clamps both worlds to kernel-R-only, no user. Enabling SPRR
  removes user-mode write+execute these pages have natively.
- **index 10 (2 leaves): executable in all three interpretations** — the sole
  ordinary-world-executable pages, consistent with a GXF gateway/trampoline that
  must run across the guarded transition.

### Finalized go-conditions (supersede the list above)

1. **SPRR enable coupled to real guarded entry only** — unchanged; the final PPERM
   leaves monitor text R-only and data R-only in the ordinary world.
2. **Exact enable sequence to reproduce** (from attempt-9/attempt-10 events):
   `CONFIG 0x1` + `PPERM 0x…baf5` (UPERM 0, PMPRR 0) → `CONFIG 0xfb`
   (enable+lock_config+lock_perm+lock_kernel_perm) + `UPERM 0x2010002030100000` +
   `PMPRR 0x40010` → **genter** → rewrite `PPERM 0x2020a52a302abae6` →
   `CONFIG 0xff` (locked). Enable only with these exact values and order.
3. **Leaf set that must validate = all 6 classes above** under the locked
   registers, decoded against the enable-point `ttbr0`/`ttbr1` snapshot. Presently
   all 6 classes are natively representable, W^X-clean in the guarded world, and
   free of hierarchy-vs-leaf mismatches → the validator passes closed. **Go-condition
   3 is met for the captured state.**
4. **Re-validate on population** — gap #1/#2 are empty; re-decode them (and any
   newly RMW-populated structure tables) at the actual enable point before relying
   on SPRR, since the tables mutate live during the run.
5. **No unexpected user access** — confirmed: only native index-4 exposes EL0, and
   SPRR removes it entirely; no leaf grants any user R/W/X under either SPRR world.

## What is and isn't claimed

- Claimed: the decode matches the pinned upstream model bit-for-bit; read is
  granted in every world for every captured leaf; the ordinary world is read-only
  under the final PPERM; the guarded world yields a coherent W^X monitor;
  native over-grants (W on text) relative to guarded; all 139 reachable leaves
  diverge native-vs-SPRR; no captured leaf is user-accessible.
- Not claimed / not validated: upstream nibble meanings on M3 silicon, PAN
  behaviour under SPRR, the semantics of APTable/PXNTable/UXNTable under SPRR,
  and the leaves behind the three uncaptured PXNTable sub-tables. None of this is
  hardware-validated; SPRR enforcement, shadow-table mirroring, and guarded-world
  continuation remain unimplemented in the probe.
