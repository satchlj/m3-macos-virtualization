# Observation-grade virtual guarded world

Attempt 3 stopped on SPTM writing `GXF_CONFIG_EL1 = 1`; the next instructions
set `GXF_PABENTRY_EL1`/`GXF_ENTRY_EL1` and execute `genter`. To observe what
the monitor does in guarded execution without enforcing anything,
`sptm_entry_probe.py --virtual-gxf` (pipeline field `virtual_gxf`) follows
the architectural control flow of `genter`/`gexit` in the host callback:

- `genter` (rewritten HVC `0x609x`): the link PC (the instruction after
  `genter`) and PSTATE are banked; on the first entry the guest's EL1
  exception bank (`SPSR/ELR/ESR/FAR/AFSR1/VBAR_EL12`) is saved and replaced
  by the staged GL1 bank (the vector base only if `VBAR_GL1` was set), and
  `SP_EL1` is swapped with the guarded stack bank. `SPSR_EL12` and
  `ELR_EL12` receive the link, `ESR_EL12` receives `0xfe010000 | imm`,
  execution continues at the staged `GXF_ENTRY_EL1` in EL1h with DAIF masked.
  `ASPSR_GL1` bit 0 records a nested entry.
- While guarded, `GXF_STATUS_EL1` reads 1 and the `*_GL1` bank registers
  access the live EL1 bank (`guarded-bank-register` events); the vector stop
  samples the swapped vector base, so a guarded-world exception still stops
  at its first recorded vector visit.
- `gexit` (`0x60a0`) returns to the possibly modified `ELR_EL12`/`SPSR_EL12`,
  captures the guarded bank back into the staged registers, restores the
  ordinary EL1 bank and `SP_EL1`, and clears the flag.
- `GXF_CONFIG_EL1` accepts 0/1 and is readable; any other value, a transition
  while GXF is disabled, `genter` without an entry point, `gexit` while not
  guarded, or a transition from EL0 stops with
  `unsupported-guarded-transition`. Without the flag the instructions stop as
  before.

The report's `virtual_gxf` block records enable state, transition counts and
config writes, with `permissions_enforced` and `guarded_pages_enforced` both
false. No SPRR permission, guarded-page protection, GL2 hardware state or
lockdown is modelled; the monitor believes it is guarded while the CPU runs
it as ordinary EL1 code. Semantics follow the architecture as reflected in
the pinned public `hv_sprr.c` (`hv_gxf_genter`/`hv_gxf_gexit`) and are
exercised only through the replay harness (`VirtualGuardedWorldTests`).

## First guarded execution on hardware (attempt 4, run `47640bc9`)

The monitor enabled GXF, staged its entry points, and `genter` was followed
into the virtual guarded world at event 7,786,860. In guarded mode it set
`TPIDR_GL2` to `0xfffffe0007106200`, wrote a guarded-world permission value
`SPRR_PPERM_EL1 = 0x2020a52a302abae6`, `SPRR_CONFIG_EL1 = 0xff`, pointed the
guarded vector base at its ordinary vector page, cleared PAN and returned into
its caller, all as the static listing predicted. Diagnostics afterward showed
the live EL1 bank holding the banked link (`ESR_EL12 = 0xfe010000`,
`ELR_EL12` at the instruction after `genter`), confirming the swap on
hardware. Forty events later it stopped writing `AGTCNTRDIR_EL12 = 3`.

A static scan of the image shows what follows: from guarded execution the
monitor programs the hypervisor configuration for the level below it,
`VPIDR/VMPIDR`, `MDCR`, `CPTR`, the `HFG*`/`HDFG*` fine-grained traps,
`HACR`, `HCRX`, stage-2 `VTTBR/VTCR/VNCR`, `ICH_*`, Apple CTRR ranges and
locks, `VMSA_LOCK`, `SPR_LOCKDOWN`, AMX controls and timer redirection, plus
twelve unnamed EL2-encoded Apple registers that were not rewritten at all.
`--stage-el2-config` (pipeline field `stage_el2_config`) records every such
write in `report['staged_el2_registers']` and returns staged values on read,
applying nothing (`staged-el2-register` events); the unnamed encodings are
now rewritten and staged with the Apple set. Translation controls keep their
validated path. This is still observation: none of that configuration exists
for a level below the monitor here, and the first time the monitor depends
on it (launching its kernel, taking a stage-2 fault) the run will stop.
