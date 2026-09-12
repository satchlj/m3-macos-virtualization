# MMU and SPTM progress — 2026-09-09

## Hardware results

The M3 passed the invalid-MMU-request test and the non-VHE MMU alias test. The latter writes guest-owned 16 KiB tables, enables guest stage 1 through the virtual EL2 adapter, reads `0x1122334455667788` at virtual address `0x40000000` from a distinct physical page, disables translation, and returns to the USB proxy. Stage 2 maps only the allocated test RAM.

A subsequent bounded probe loaded the matching SPTM/TXM/BootKC copies into a segmented guest RAM image and executed SPTM's initial instructions. It did not boot macOS or enter TXM. The monitor layout follows pinned public QEMU source; the ADT is copied, with new guest ranges and revision-3 bootargs. No MMIO is mapped. Existing peripheral descriptions are not access permissions; this is an entry probe, not a validated complete device model.

The trace established these requirements in sequence:

1. SPTM writes zero to `OSLAR_EL1`. A host-side guest-only unlocked state lets the trace proceed without changing host debug controls.
2. SPTM requests `HCR_EL2 = 0x408000000` (E2H and TGE). This requires a VHE translation regime, not just the non-VHE regime tested first.
3. It clears `CNTVOFF_EL2` and Apple encoding `S3_1_C15_C9_4`, publicly listed as AGTCNTVOFF_EL2. The probe models only zero virtual offsets. Nonzero offsets are unsupported; host counter offsets are untouched by these handlers.
4. It completes a memory-initialization loop before requesting `SPRR_PPERM_EL1 = 0x2020a52a302abaf5`. The probe stages this value while translation is disabled.

Untranslated privileged accesses initially became undefined instructions at physical EL1 and entered SPTM's own exception loop. Saved EL12 syndrome/return state pinpointed the faulting operation. The instruction adapter now intercepts the additional known controls so unsupported requests stop at the host. No proprietary function disassembly was produced; faulting register encodings were matched to public architectural register definitions.

## Implemented MMU subset

The C engine now validates a complete 42-bit VA/PA, 16 KiB, low-address translation configuration. A nonzero aligned TTBR0, the supported TCR value, and MAIR attribute 0 = normal WB memory are required. Only the modelled SCTLR.M transition is accepted; cache-enable and other unmodelled controls stop. Live TCR/TTBR/MAIR/HCR changes are rejected. Virtual ERET with active translation remains unsupported.

The adapter programs guest EL12 registers, never host translation roots. It converts non-VHE EL2 PS into EL1 IPS and disables the unused TTBR1 walk. It invalidates guest translations on transitions. Disabling the virtual layer also clears its active guest translation state.

The tested build supports HCR E2H+TGE and the corresponding constrained VHE TCR format (`0x34096b516`). The VHE build passes host tests and builds natively; the VHE alias test has also passed on the M3. This does not yet provide dynamic EL1-register aliases, arbitrary monitor TCR/TTBR1 configurations, SPRR permission mirrors, GXF worlds, or a complete monitor exception model.

## Probe versus runtime implementation

`scripts/sptm_entry_probe.py` is a bounded observation harness. Its host-side shadows for HCR, disabled SCTLR, zero counter offsets and staged SPRR permission registers are not the complete C runtime. By default it stops before enabling monitor translation. The opt-in `--allow-monitor-mmu` backend admits only the captured VHE profile after bounded page-table checks. This backend enabled the monitor MMU on hardware and continued execution; the C runtime still supports only the constrained smoke-test profile. Translated SPRR activation, GXF, and virtual ERET remain explicit stops. The single-step budget counts host-visible trace events; supported HVC operations also execute host emulation code outside that count. Instruction stepping is diagnostic and may affect monitor behavior.

The latest probe stages SPRR permission values and enable state while translation remains off, matching the public emulator’s deferred mirror construction. Both SCTLR aliases are intercepted; translation enable requires the explicit profile option. Both EL1/EL2 aliases of TCR, TTBR0/1 and MAIR route to guest EL12 banks, with live changes rejected. The latest alias guard and error-cleanup changes were exercised on hardware through the MMU transition and a clean proxy return. GXF activation remains unsupported. The public `hv-sprr` branch contains permission mirrors and guarded-world machinery; these need integration with virtual EL2/VHE contexts. Its documented permissive treatment of some permission combinations must be considered before treating it as an accurate SPTM model.

## Reproduction and device state

Use README bootstrap and the pinned experimental patch. `scripts/vel2_smoke.py` supports `transition`, `reject-mmu`, `mmu-alias`, and `mmu-vhe`. Without `--execute`, compilation is offline. `scripts/sptm_layout.py` builds an offline layout manifest from restored images. The entry probe requires explicit `--execute`, `--device`, and a bounded `--steps` value.

A RAM reload after a previous hypervisor session lost USB. The log cannot distinguish a physical connection loss from a reload failure. Reloading from a fresh baseline succeeded. Use a fresh dedicated-test proxy boot for a new image; do not presume post-hypervisor RAM reload is reliable. The installed baseline remained unchanged.

## References

- Public loader: https://github.com/jprx/qemu-sptm/blob/6c3ca665bab9a08399f4681e4ada43bfcfb7d493/hw/arm/xnuboot_sptm.c
- Public SPRR model: https://github.com/AsahiLinux/m1n1/blob/1c98fd09817cede0043d25c95fb540dbd683ef18/src/hv_sprr.c
- Arm translation regimes: https://developer.arm.com/documentation/ddi0487/mc/-Part-D-The-AArch64-System-Level-Architecture/-Chapter-D8-The-AArch64-Virtual-Memory-System-Architecture/-D8-1-Address-translation/-D8-1-3-Relationship-between-translation-regimes-and-implemented-Exception-levels
- Published Apple register listing (naming evidence, not a complete semantic specification): https://gist.github.com/justtryingthingsout/fbfbd44fac58434ffbfb9e9666e3e07e

## Monitor translation boundary and host power interruption

The trace passed the APSTS ready-bit poll after adding the fixed guest VMKEY/APSTS initialization used by public `HV.init`. APCTL and kernel-key accesses use the public guest EL12 redirects. SPTM then requested SCTLR `0x02001010fc14793d` with HCR `0x408000000`, TCR `0x10800236511a511`, MAIR `0x0c0804ff00bb44ff`, two guest-owned translation roots, and SPRR disabled. The TCR profile uses 47-bit virtual addresses, 42-bit physical addresses and 16 KiB granules; it exceeds the small C smoke-test subset.

The first opt-in MMU attempt stopped before enabling translation because the harness incorrectly required an identity mapping for the monitor stack. The stack mapping is intentionally non-identity. The corrected check permits a translated stack within owned guest RAM, while retaining identity checks for the immediate PC and bootargs and checking leaf access/write/execute flags. These checks are narrow entry checks, not a complete page-table permission model.

The retry failed opening the USB serial device, before guest execution. The user reported that the Codex host lost power while the M3 remained powered on. The host currently sees no USB proxy; cable re-enumeration is pending. Do not infer an M3 crash or successful monitor MMU enable from this interruption. Verify the live image before continuing; no installed boot object was changed.

## Resumed USB and first monitor MMU execution

Rebooting the dedicated test installation restored USB. The installed baseline passed immutable image verification, and the VHE build was RAM-loaded successfully. A fresh probe exposed unmasked entry interrupts: execution diverted to offset `0x300` before the first monitor instruction. The entry guard now sets DAIF masks before resuming; single-step events continued on hardware.

The next validation failure was the original physical BootArgs address, which is not mapped in the monitor's new regime. PC and translated stack checks passed. The harness now records an unmapped original BootArgs address without requiring it for immediate execution; any later access still remains subject to guest translation and stage 2. SPTM's requested SCTLR was then applied, and the trace advanced beyond the enabling instruction. A later undefined instruction entered its high-VA exception vector. The run reached its budget and returned to a responsive proxy after guest MMU cleanup.

Saved guest syndrome identified the undefined instruction as the public `VM_TMR_FIQ_ENA_EL2` encoding, writing XZR. The probe-specific zero/disabled shadow passed on hardware; nonzero writes remain unsupported. The next access was an unimplemented MDSCR_EL1 read, which stopped cleanly at the host. This establishes initial monitor translation execution, not successful monitor initialization or a macOS guest boot. Handler validation errors now exit normally before cleanup so the pending hypervisor reply is consumed in order.
