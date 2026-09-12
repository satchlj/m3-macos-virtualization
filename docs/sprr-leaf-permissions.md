# SPRR-aware leaf permission decoding

When SPRR is enabled, a stage-1 leaf's AP[2:1] (bits 7:6), UXN (54) and PXN
(53) stop meaning ordinary Arm permissions. Together they select a 4-bit
index, and the effective kernel/user RWX come from the nibble of
`SPRR_PPERM_EL1` / `SPRR_UPERM_EL0` at that index. A hardware run showed SPTM
enabling SPRR with `PPERM_EL1 = 0x2020a52a302abaf5` and
`UPERM_EL0 = 0x2010002030100000`; with SPRR not enforced by our probe, the
monitor's exception-handler data page then faulted under PAN because its
index bits look like an EL0-accessible AP encoding.

## Index layout (pinned upstream)

Taken verbatim from `local/m1n1-vel2/src/hv_sprr.c` (`SPRR_IDX_*`,
`sprr_perm_nibble`, `sprr_mirror_entry`) with PTE bit positions from its
`memory.h`:

| index bit | upstream name    | descriptor bit |
|-----------|------------------|----------------|
| 0         | `SPRR_IDX_PXN`   | 53 (PXN)       |
| 1         | `SPRR_IDX_UXN`   | 54 (UXN)       |
| 2         | `SPRR_IDX_AP_EL0`| 6 (AP[1])      |
| 3         | `SPRR_IDX_AP_RO` | 7 (AP[2])      |

Nibble = `(perm >> (index * 4)) & 0xf`; `sprr_el_rwx` (ordinary world) or
`sprr_gl_rwx` (guarded world) maps that nibble to RWX with R=4, W=2, X=1.
Nothing in this layout was ambiguous in the pinned source.

## What was added

- `scripts/sprr_permissions.py`: `leaf_index` and `leaf_permissions(descriptor,
  perm_el1, perm_el0, world='ordinary')`, a pure function returning the index,
  its bit breakdown, both selected nibbles, explicit `kernel_read/write/execute`
  and `user_read/write/execute` booleans, the native (SPRR-off) reading of the
  same bits, and `representable_natively` from the existing exact audit.
- `scripts/guest_pt.py`: `validate_monitor_entry` and `validate_root_switch`
  accept `sprr=None` (default, unchanged behaviour and output) or
  `sprr=dict(pperm=..., uperm=..., world='ordinary')`. In SPRR mode every
  checked mapping gains an `sprr` view alongside the native fields, and the
  continuation requirements (PC and vector kernel-executable, stack
  kernel-writable, stack not user-accessible when PAN is requested) are applied
  to the SPRR-effective permissions instead of the native ones. It fails closed
  on a guarded-world request, a malformed state, any effective pair an ordinary
  leaf cannot express exactly, and any detected hierarchical table restriction
  (upstream ignores those under SPRR because their meaning is unknown).
- `scripts/sprr_leaf_permissions.py`: CLI printing the interpretation as JSON,
  e.g. `python3 scripts/sprr_leaf_permissions.py 0x20000403 0x2020a52a302abaf5
  0x2010002030100000 [--world guarded]`, for decoding a captured leaf by hand.

For the recorded registers the ordinary-world indices decode to kernel
`RX, RW, R, RW, R, R, -, RW, R, R, RX, R, -, R, -, R` and user
`-, -, -, -, -, RX, -, RW, -, R, -, -, -, RX, -, R` (index 0..15); all sixteen
pairs are natively representable. The guarded world gives no user access at
any index.

## What is and is not claimed

- Claimed: the decoding matches the public upstream model bit for bit, the
  default (SPRR-off) validator path is unchanged, and the SPRR mode never
  grants more than the model says.
- Not claimed: the upstream nibble meanings, PAN behaviour under SPRR, or the
  effect of APTable/PXNTable/UXNTable under SPRR have been validated on M3
  hardware. Every result carries `hardware_validated: false`.
- Not implemented: shadow-table mirroring, guarded-world continuation, or any
  SPRR enforcement in the probe. A hierarchical restriction that has no native
  effect and is therefore undetectable from the leaf result (for example
  APTable privileged-only over a leaf whose AP[1] is already clear) is not
  flagged.

Tests: `SprrLeafPermissionTests` (exhaustive over the 16 indices for the
recorded values, both worlds), `SprrMonitorEntryTests`, `SprrLiveRootTests`
and `SprrLeafCliTests`.
