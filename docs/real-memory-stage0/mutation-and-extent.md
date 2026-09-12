# Stage-0 — what the monitor mutates, and how it learns physical extent

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Read-only offline analysis of `local/payload/sptm.macho` against the attempt-9
bundle (`artifacts/runs/observe-sprr/attempt-9`). No device, probe, or pipeline
was touched. This answers the two Stage-0 open questions from
[real-memory-phase-plan.md](../real-memory-phase-plan.md): the shape of the
monitor's runtime-structure writes, and the provenance of its physical-memory
extent.

## Address mapping used

`sptm __TEXT_EXEC` (`__text`) links at vmaddr `0xfffffff0270a0000`, fileoff
`0x9c000`, size `0x5c000`; the guest maps it at VA base `0xfffffe00070a0000`
(`virtual_base 0xfffffe0000000000` + placement offset `0x70a0000`). The
task's "`__TEXT_EXEC+0xbb8b8`" is a **file offset** in `sptm.macho`:
`0xbb8b8 − 0x9c000 = 0x1f8b8` into the segment → guest VA `0xfffffe00070bf8b8`
(link VA `0xfffffff0270bf8b8`). The trace confirms it: `instruction-step`
events land on these PCs with `FAR = 0xfffffe0038025008` = region-A base
`0xfffffe0038020000 + 0x5008`.

## Task 1 — the mutation (read-modify-write) function

### Enclosing function
Body: link `0xfffffff0270bf4c4 … 0xfffffff0270bfb84` (guest
`0xfffffe00070bf4c4 … 0xfffffe00070bfb84`); prologue `pacibsp; sub sp,#0x90;
stp x24..x19,x29/x30`. It is an SPTM image/region-registration + managed
descriptor-init routine in the `sptm_init` flow. Just before the RMW
(`0xbf000–0xbf104`) it resolves the monitor's own image regions by name via
`init_get_image_region` (helper `0xbcc98`) — the C-strings are `CL4-entry/-rx/
-virt`, `TXM-entry/-ro/-virt`, `BootKC-entry/-ro/-virt` — computes each extent
(`virt + entry − ro`) and stores them into a config block at guest
`0xfffffe0007098000` (`+0x920/0x928/0x930`). It then PAC-signs and registers
callback pointers (`xnu_el2_exception_vector`, `xnu_ctrr_dispatch_table` via
`0xe7fd4`) and performs the descriptor RMW.

### Context base and pointer table
`x9 = TPIDR_EL2` — the per-CPU SPTM context (trace value
`x9 = 0xfffffe0007106200`, in sptm `__common`). Structure pointers are loaded
from fixed offsets in it (values from trace register snapshots):

- `*(x9+0x12f8) = 0xfffffe0038020000` — region A base
- `*(x9+0x1308) = 0xfffffe0038070000` — region B base

(These match the CONTEXT FACTS. The pointer table has more live slots:
`0x12d0,0x12e0,0x12e8,0x12f0,0x12f8,0x1300,0x1308` are all written elsewhere,
so there are more than two managed regions overall.)

### The exact writes (disassembly + trace-verified operands)
Region A (base `0xfffffe0038020000`):
- `0xbf8b8 ldr x14,[x9,#0x12f8]` · `0xbf8bc ldr xzr,[x14,#0x5008]` (discard
  read) · `0xbf8c0 mov x15,#-1` · `0xbf8c4 str x15,[x14,#0x5008]` →
  **A+0x5008 ← 0xFFFFFFFFFFFFFFFF** (plain store of all-ones).
- `0xbf8cc ldr x14,[x9,#0x12f8]` · `0xbf8d0 ldr x15,[x14,#0x5000]` ·
  `0xbf8d4 orr x15,x15,#1` · `0xbf8d8 str x15,[x14,#0x5000]` →
  **A+0x5000 |= 0x1** (RMW, sets bit 0).

Region B (base `0xfffffe0038070000`) — the pattern quoted in the task:
- `0xbf91c ldr x14,[x9,#0x1308]` · `0xbf920 mov w15,#0x9008` ·
  `0xbf924 add x14,x14,x15` · `0xbf928 ldr x15,[x14]` ·
  `0xbf92c orr x13,x15,x13` · `0xbf930 str x13,[x14]` →
  **B+0x9008 |= x13** (RMW).
- `0xbf938 ldr x8,[x9,#0x1308]` · `0xbf93c add x8,x8,#0x9000` ·
  `0xbf940 ldr x13,[x8]` · `0xbf944 orr x13,x13,#1` · `0xbf948 str x13,[x8]` →
  **B+0x9000 |= 0x1** (RMW, sets bit 0).

### The OR'd flag value (x13)
Computed at `0xbf8f8 mov x13,#-0x800000000001` (= `0xFFFF7FFFFFFFFFFF`, all
bits set except bit 47) then `0xbf8fc csinv x13,x13,xzr,eq`: on the `eq` path
`x13 = 0xFFFF7FFFFFFFFFFF`; otherwise `x13 = ~0 = 0xFFFFFFFFFFFFFFFF`. The
condition (`0xbf8e0–0xbf8f4`) is `(w10 & 0xffe0)==0x420` **or**
`(w10 & ~0x10)==0x500`, where `w10` is a device/register-class id
(trace `x10=0x612f0430` → `&0xffe0 = 0x420`, so `eq` is taken and the trace
value is `x13 = 0xffff7fffffffffff`).

Interpretation: the descriptors are paired 16-byte slots — word0 (offset
`…000`) carries a **valid/enable bit (bit 0)** and word1 (offset `…008`) a wide
**permission/ownership bitmap** set to (near-)all-ones. The monitor is
granting full rights in freshly-referenced metadata slots.

### Loop vs straight-line; init vs update
- **Straight-line, fixed-offset field initialization**, guarded by world/mode
  checks. Target offsets (`0x5000/0x5008/0x9000/0x9008`) are immediate
  constants, not induction variables. **There is no iteration over the pointer
  table or over array entries in this span.**
- The only backward edge into the RMW span (`0xbfa1c tbnz → 0xbf91c`) is a
  **guarded-world re-check/retry**, not a data loop: `0xbf908–0xbf918` test
  guarded status registers (`S3_6_C15_C8_0`, `S3_6_C15_C11_1`) and the
  fallback at `0xbfa14` reads the per-CPU context byte `[ctx+2]` and re-enters
  `0xbf91c`. This is exactly the virtual-GXF divergence surface from the
  observation phase.
- **Semantics = initialization** (OR-ing enable/permission bits into
  descriptor words), matching the observation doc's "RMW OR a flag into an
  existing value." Because it **reads before it writes**, a zeroed sandbox
  cannot supply the content it expects.

## Task 2 — how the monitor learns physical-memory extent

**Source = the Apple Device Tree (ADT). Not a hardware/Apple system register,
not a hardcoded constant.** Three DT-fed paths:

### 1. DRAM extent from `/chosen` `dram-base` / `dram-size`
The bootstrap-args registration function at `0xfffffff0270dcfb8` looks up DT
node `"/chosen"` (`0x010060`) via the node finder `0xbc604`, then reads
properties `"dram-base"` (`0x0101ac`) and `"dram-size"` (`0x02010b`) via the
property getter `0xbc820`. It records into the config block at guest
`0xfffffe0007099000`:
- `dram-base` → `+0xc70`; `dram-base + dram-size` → `+0xc78` (DRAM end).
- It also takes `phys_base`, `virt_base`, and a span in args and records
  `phys_base → +0xd0`, `virt_base → +0xc60`, `virt_base+span → +0xc68`, and
  `span >> 14` (= **DRAM page count at 16 KB pages**) → `+0x260`.

### 2. `phys_base`/`virt_base` from the boot handoff
`sptm_init` (`0xfffffff0270bddac`) copies a `0x488`-byte boot-handoff struct
(arg `x0`) into `0x098000+0x498`, then sets `phys_base = handoff[+0x8] → +0xd0`
and `virt_base = handoff[+0x10] → +0xc60`. The slide is handed in by the prior
boot stage; it is **not** read from a register. (`phys_base` at
`0x099000+0xd0` is the global read at ~90 sites for every VA↔PA conversion.)

### 3. Region/descriptor bases from `chosen/memory-map`
`init_get_image_region` (`0xbcc98`) resolves named entries out of DT
`chosen/memory-map` (strings `chosen/memory-map` `0x006690`, `DT memory-map is
NULL` `0x006636`, `error … looking up chosen/memory-map` `0x006690`). This is
how CL4/TXM/BootKC and the managed-metadata regions (region A/B pointers) are
located. Carveouts come from DT too: `chosen/carveout-memory-map` (`0x007e19`)
and named props `gpu-region-base/-size`, `gfx-shared-region-*`,
`gfx-handoff-*`, `uat-vaddr-size`, `uat-mapping-limit`.

### The memory map becomes an internal bounded table
PA↔VA translation iterates a table built from the memory map: each entry is
`0x18` bytes `{ base_paddr @0x0, slide @0x8, npages(w) @0x10 }`; the loop is
**bounded by a stored entry count** (`[x?+0xb70]`), steps `+0x18` per entry,
and each region spans `npages << 14` (SPTM_PAGE_SIZE = 16 KB). Seen at
`0xdb434–0xdb46c` and `0xc0440–0xc0488`.

### `dram_size` as a bound (and where AMCC fits)
`dram_size` bounds bootstrap CTRR-protected frame allocation
(`bootstrap_alloc_frames`; panics `Exceeded … bootstrap SPTM CTRR-protected
frames, dram_size=%#llx` `0x00fb07`, `… xnu CTRR-protected frames …`
`0x00fb75`). AMCC/CTRR system registers (`ctrr_amcc_find_lock_group_data`,
`amcc-ctrr-a`, `assert_amcc_cache_disabled`) are used to **lock** the CTRR
region on hardware, but the **extent value itself is the DT `dram-size`**, not
an AMCC readout.

## Implications for the real-memory phase

- The monitor **reads** descriptor content before OR-ing flags in (RMW), and it
  expects a valid ADT exposing `/chosen` `dram-base`/`dram-size` and
  `chosen/memory-map`. A zeroed, isolated sandbox satisfies neither — matching
  the observation-phase boundary.
- The R1 backing set is not just regions A and B: the context pointer table
  (`x9+0x12d0 … +0x1308`) references several managed structures, and the DT
  memory-map/carveout entries define the physical layout the monitor will walk.
  Backing must be driven from the DT memory map the monitor itself parses, so
  its extent notion and the DRAM we supply agree (the plan's prereq 2/open
  question 3).
- Descriptor slots are 16-byte `{ flags(bit0 valid), permission-bitmap }`
  pairs; the observed indices are `0x5000` (A) and `0x9000` (B). Full structure
  sizes are not bounded by this single trace path.

### Key offsets (guest addresses)
| item | address |
| --- | --- |
| RMW function body | `0xfffffe00070bf4c4 … 0xfffffe00070bfb84` |
| region A base `*(TPIDR_EL2+0x12f8)` | `0xfffffe0038020000` (IPA `0x211050000`) |
| region B base `*(TPIDR_EL2+0x1308)` | `0xfffffe0038070000` (IPA `0x211e40000`) |
| config block | `0xfffffe0007098000` / `0xfffffe0007099000` |
| `phys_base` global | `0x099000 + 0xd0` |
| `virt_base` / `virt_end` | `0x099000 + 0xc60 / +0xc68` |
| DRAM page count | `0x099000 + 0x260` |
| `dram-base` / DRAM end | `0x099000 + 0xc70 / +0xc78` |
| `init_get_image_region` | `0xfffffe00070bcc98` |
| `/chosen` dram-base/-size reader | `0xfffffe00070dcfb8` |
