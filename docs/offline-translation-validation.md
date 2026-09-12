# Offline translation and exception validation — 2026-09-09

The suite now has **134 passing tests, no skips**, with 57 added after the
disabled guest debug model. All work here was target-free. Native source and
patches were unchanged; the changes to the Python probe are not hardware-tested.

## Page-table checks

The bounded walker now rejects out-of-range physical-address bits instead of
masking them into a different address. The supported profile requires plain,
aligned, untagged 42-bit roots and aligned 32 MiB blocks. It still walks only
16 KiB tables in the two 47-bit VA regions, with level-2 blocks or level-3 pages.
ASID/CnP-bearing roots and misaligned blocks are conservative probe stops, not
claims that every such encoding necessarily faults on every Arm implementation.

Parent APTable/PXNTable/UXNTable restrictions are accumulated into the leaf
result. The immediate-entry validator checks executable identity-mapped code,
a writable 16-byte stack window that may be nonidentity-mapped, physical
ownership, access flags, alignment, and the effect of PAN on a user-accessible
stack. User-writable code is rejected for privileged execution. Code and stack
must use the captured normal-WB MAIR encoding. These are deliberately narrow
entry checks, not a complete memory-permission emulator.

An absent original BootArgs mapping remains optional. A malformed descriptor,
out-of-allocation table, or failed table read at that address now stops instead
of being mistaken for an optional absent mapping.

Tests exercise VA index boundaries in both ranges; truncated pages; root,
descriptor, block and allocation errors; inherited permissions; PAN; memory
attributes; missing mappings; and invalid BootArgs tables. Synthetic page-table
pages are created from scratch. The retained hardware reports do not contain
the complete table pages, so this is not a replay of the captured MMU walk.

## Translation-control callback tests

The virtual endpoint now supports sparse guest RAM, a whitelist of guest EL12
register banks, and barrier recording. Synthetic MRS/MSR instructions pass
through the probe's actual instruction rewriter and register-index ordering,
then the actual exception callback and upstream ExcInfo serializer.

The tests check both EL1 and EL2 aliases, XZR, the exact supported enable
profile, required opt-in/VHE/SPRR state, enable and disable ordering, rejection
without register writes, and return-PC handling. An identical live bank write
now resumes without physically rewriting that bank. Changed live controls
still stop. Disable requests explicitly synchronize the SCTLR write before
TLBI. Translated SPRR activation, GXF, and virtual ERET remain stops.

Fake barriers record requested order only: they do not model TLB/cache effects,
CPU ordering, USB timing or host/guest register banking on the M3. Only the
whitelisted translation banks are available; other hardware accesses fail.

## Exception transitions and failure handling

The Python callback now distinguishes asynchronous exceptions before decoding
ESR, preventing a stale syndrome on IRQ/FIQ/SError from being treated as a fresh
synchronous guest instruction. A spent event budget stops before a new trap's
emulation effects. A failed report save now still sends exactly one guest-exit
reply. Tests cover both accepted entry guards, invalid entry PCs, single-step
resumption, unhandled exceptions, and injected context/report write failures.

The actual portable C virtual-EL2 state machine is compiled and tested on the
host. Added tests cover all 256 NZCV/virtual-DAIF combinations through HVC/ERET,
same-level returns, repeated stack round trips, unsupported PSTATE fields and
modes, vector errors, nested-HVC rejection, and reset. Native live-control
writes remain more restrictive than the Python probe: even identical writes
are unsupported in that smaller C model. No complete exception/interrupt model
or translated ERET implementation is claimed.

## Reproduce

```sh
source setup/activate.sh
python -m unittest discover -s tests -v
python scripts/replay_debug_probe.py --report local/reports/debug-replay.json
python scripts/sptm_entry_probe.py --payload local/payload \
  --report local/reports/sptm-entry-offline.json
```

The latter two commands remain offline. The debug CLI replays only the two
debug traps, while the expanded synthetic translation/exception scenarios run
in the test suite. No new dependencies or native build are needed after the
previous environment bootstrap.

## Architectural basis and remaining checks

The [Armv8.1 architecture supplement](https://documentation-service.arm.com/static/5fb7d32fd77dd807b9a80c61),
`AArch64.TranslationTableWalk` and `AArch64.CheckPermission` (PDF pages 792 and
804–806), supplies the public address-size and permission rules used here.
Its VHE TCR description places HPD0/HPD1 at bits 41/42; both are clear in the
captured profile. The fixed profile also has hardware AF/dirty updates disabled.
The probe does not generalize these rules to different TCR configurations or
newer optional permission mechanisms. Barrier ordering is also compared with
the project's pinned native `src/hv_vel2.c` adapter.

Before a hardware continuation, use the fresh baseline, interface/proxy NOPs,
and immutable image comparison from the pause checkpoint. Check that the stricter
entry validator accepts the live monitor tables, then observe the first operation
after the MDSCR read. Hardware cache/TLB behavior, SPRR/GXF, and macOS guest boot
remain unverified by this work.
