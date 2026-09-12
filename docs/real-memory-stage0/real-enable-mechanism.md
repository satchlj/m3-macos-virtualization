# Real SPRR/GXF enable — mechanism resolution (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

How `--real-guarded` must apply the guest's SPRR/GXF/guarded state, resolved by
three safe hardware iterations plus offline mapping of the early (pre-MMU) setup.
No hardware was harmed; each attempt exited cleanly.

## The early setup the monitor performs (pre-MMU)

Confirmed by disassembly of the attempt-14 trace (`sptm/__TEXT_EXEC` around
`+0xab700`) and the sysreg tables:

```
msr S3_6_C15_C1_0, x0   ; x0=1  -> SPRR_CONFIG_EL1 = 1   (enable), executes fine
...
msr S3_6_C15_C1_6, x0   ; x0=PPERM -> SPRR_PPERM_EL1     (permissions)  <-- EC-0 undefined
```

`S3_6_C15_C1_0 = SPRR_CONFIG_EL1`, `S3_6_C15_C1_6 = SPRR_PPERM_EL1` (op1=6). The
monitor enables SPRR then writes the permission registers, all pre-MMU. On real
hardware this works; under our EL2 hypervisor the `SPRR_PPERM_EL1` access is EC-0
undefined — EL1 SPRR is gated by EL2, and the guest's own `SPRR_CONFIG_EL1=1`
does not lift that gate.

## Three mechanisms, one correct

| Attempt | Mechanism | Result |
|---------|-----------|--------|
| 13 | HV `u.msr(SPRR_CONFIG_EL1, …)` (EL1 name from EL2) | Writes the HV's own copy under VHE; guest GXF never enabled, native genter stayed EC-0. |
| 14 | Native execution (don't rewrite the regs) | Guest's `SPRR_PPERM_EL1` write EC-0 undefined — EL1 SPRR gated by EL2. |
| **now** | **EL12-alias redirect** (`HV.MSR_REDIRECTS`) | The vel2 HV's own mechanism: `SPRR_CONFIG_EL1→SPRR_CONFIG_EL12`, `SPRR_PPERM_EL1→SPRR_PPERM_EL12`, `GXF_*→GXF_*_EL12`, applied from EL2 to the guest's EL1 bank. |

The vel2 HV already redirects `APCTL_EL1`/`KERNKEY_EL1` this way; `HV.MSR_REDIRECTS`
maps the whole SPRR/GXF family to `_EL12`/`_EL02`/`_GL12` aliases, and it only
falls back to EL2 emulation when `apple_sysregs_unlocked` is false (ours is true).
So the alias redirect is the intended path.

## What `--real-guarded` now does

- **First branch:** any register in `HV.MSR_REDIRECTS` is applied via its EL12
  alias (`u.msr(HV.MSR_REDIRECTS[reg], value)` / `u.mrs` on read). This covers
  `SPRR_CONFIG`, `SPRR_PPERM`, `SPRR_UPERM`, `SPRR_AMRANGE`, `SPRR_UMPRR`,
  `GXF_CONFIG/ENTRY/PABENTRY`, the `GL1` bank, `APCTL`, keys. The `SPRR_CONFIG`
  write records the enable point (value + ttbr controls) to `sprr_real_enable`.
- **genter/gexit stay native** (instructions, no alias) — now defined because GXF
  is really enabled on the guest via `GXF_CONFIG_EL12`.
- Attempt-13's `u.msr(EL1)` apply and attempt-14's native-skip are reverted.

## Open item

`SPRR_PMPRR_EL1` and the `SPRR_*_SH{1,2,3}` permission variants are **not** in
`HV.MSR_REDIRECTS` (no EL12 alias in the map). They currently stage. If the monitor
writes them before the first genter and their absence breaks guarded execution, a
mechanism for them is needed (add their aliases to the map, or another path). The
immediate fault (`SPRR_PPERM_EL1`) is redirectable and fixed.

## Next hardware test (when target M3 is reconnected)

Re-run the `--real-guarded` config (fresh-boot gate first). Expected: the SPRR
permission writes now apply via aliases (no early EC-0), SPRR really enables, and
the native `genter` transfers to the dispatcher at `GXF_ENTRY = 0xa4524` —
**first real guarded execution**. Watch for: the next dependency (a staged
non-redirectable perm, or a guarded-handler register), and confirm the HV keeps
control (single-step across the world switch).
