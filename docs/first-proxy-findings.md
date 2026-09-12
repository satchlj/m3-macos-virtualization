# First proxy findings — 2026-09-09

> Historical research context. Status and proposed next steps below describe the
> original investigation. See [current project status](STATUS.md) for later
> results and remaining milestones.

## Running build

The installed raw image reached proxy mode on the M3/J613. USB transport handshake and proxy NOP succeeded. After accounting for AArch64 RELATIVE relocations, the running `.init` (2,468 bytes), `.text` (327,680 bytes), and `.rodata` (73,504 bytes) match the local `m1n1-raw.elf` exactly. This checks code/read-only build identity, not mutable state. The Mach-O ELF uses a different layout and is not the comparison target for the installed raw boot object.

Bootargs revision 3/version 2 was read from the running proxy. ADT identifies cpu4 as running among cpu0–cpu7. Exact firmware is `mBoot-18000.161.10`. SEPFW, TrustCache, SPTM and TXM names are present in the memory map. Presence of monitor image entries is not evidence that the monitors are active. CPUFeatures reports `apple_sysregs_unlocked`, `mmu_sprr`, `actlr_el2`, and `counter_redirect` true. No HV initialization or guest execution has been attempted.

## Concrete entry-contract question

Apple public XNU commit `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` (xnu-12377.1.9, 2025-10-16) contains two materially different entry paths. This is public-source evidence, not identification of the installed 25G83 kernel build.

- Ordinary `osfmk/arm64/start.s` documents bootargs in x0.
- `osfmk/arm64/sptm/start_sptm.s` documents a boot-reason sentinel in x0, iBoot arguments in x1, and SPTM arguments in x2. Its cold path invokes SPTM before entering C initialization.
- `osfmk/arm64/sptm/arm_init_sptm.c` registers an exception return handler with SPTM, copies the SPTM argument structure and consumes monitor-provided memory information.
- The pinned m1n1 loader calls `hv_start(entry, bootargs_address)`; remaining entry registers default to zero. It does not establish the above SPTM boot argument contract.

Therefore, if the matching Tahoe payload uses the documented SPTM entry path, merely recognizing its firmware string or changing the bootargs serializer cannot make this loader compatible. The actual payload must first be identified; no guessed sentinel or fabricated monitor state will be substituted. No proprietary disassembly was used for these findings.

## Next step

The test kernel collection was copied from its matching test-installation Preboot
directory. Source and host SHA-256 matched. It was extracted with PyIMG4 0.8.8;
images and the extraction environment remain outside Git.

The payload's version string matches the running same-build daily kernel: Darwin 25.6.0 / xnu-12377.161.14~5 / RELEASE_ARM64_T8122. The test System plist still reports 25G83. Public source inspected above is an older release and does not prove all shipping details.

Actual Mach-O metadata: ARM64e fileset, 351 fileset members, outer UNIXTHREAD entry in `__TEXT_BOOT_EXEC`, and `__DATA_SPTM` present in both outer fileset and embedded kernel. These are concrete markers consistent with the public SPTM entry layout. `scripts/inspect_guest_payload.py` now reports `blocked-pending-monitor-contract` for this payload. It is an offline diagnostic, not an integrated runtime loader guard. All 29 research tests pass, including eight new synthetic payload tests. The original preflight still passes its limited structural checks; it did not inspect this payload.

Next work is monitor-aware entry/initialization, not a firmware alias. The public XNU checkout references `sptm/sptm_xnu.h` and libsptm structures but does not include the referenced header in its tree. No exact shipping bootstrap structure or working SPTM guest integration has been established. The original one-argument guest command has not been run. Leave the target in daily macOS until the next justified proxy experiment is prepared; the custom boot object remains installed.

Sources:
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/sptm/start_sptm.s
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/sptm/arm_init_sptm.c
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/start.s
