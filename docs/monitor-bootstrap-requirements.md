# Monitor bootstrap investigation — 2026-09-09

> Historical research context. Status and proposed next steps below describe the
> original investigation. See [current project status](STATUS.md) for later
> results and remaining milestones.

## Result and current blocker

The next missing component is an SPTM-aware guest boot harness, including monitor execution-level virtualization. The public m1n1 `hv-sprr` branch provides useful SPRR/GXF emulation but does not by itself provide the SPTM/TXM loader or the EL2 monitor execution environment identified in the public reference loader. No target writes, replacement m1n1 installation, or guest launch occurred during this investigation. The target remains in daily macOS.

This is a limitation of the inspected implementation, not proof that Tahoe-on-M3 is impossible. Asahi's August progress report describes successful monitor virtualization work, but the report is not a complete runnable implementation or a Tahoe 25G83/M3 support claim.

## Public implementations inspected

| Source | Exact revision | Finding |
|---|---|---|
| AsahiLinux/m1n1 `hv-sprr` | `1c98fd09817cede0043d25c95fb540dbd683ef18` | Three emulation commits atop `c9ef56f`; independent host build succeeds, Python tests 9 passed / 5 skipped. |
| AsahiLinux/m1n1 `gxf-stack` | `547999297df9d485f5ebaf3ee4dd67f83ed0f11f` | Scoped source search did not find an SPTM loader. |
| m1n1 PR #622 | `ce1c1574757e19acc44fdd28fa49c7a500a23210` | Public description explicitly requires a separate virtualized SPTM companion/emulator; reported test used an unpublished emulator and did not test M1–M3. Not deployed here. |
| jprx/qemu-sptm | `6c3ca665bab9a08399f4681e4ada43bfcfb7d493` | Public source supplies a concrete monitor-first memory layout and entry reference, not a directly portable m1n1 loader. |
| Apple XNU | `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea` | Public SPTM-to-XNU entry and initialization dependencies. Older than the actual xnu-12377.161.14 payload. |

The pinned baseline and its local patch remain intact. Alternate m1n1 revisions use separate host worktrees. None of their binary patchers has been run against the user's kernel or monitor payloads.

## Bootstrap sequence established from public source

1. Construct a consistent guest layout containing SPTM, TXM, kernel collection, trustcache, ADT and bootargs. The QEMU loader places kernel/TXM protection-class segments into explicit ADT ranges; it does not simply append whole images to the existing one-image loader. Its virtual-stride assumptions and bootargs revision need independent validation for this target.
2. Enter SPTM first. QEMU's `xnuboot_sptm.c` sets initial PC to the loaded SPTM entry and x0 to bootargs. Its `darwin.c` resets an EL2-capable CPU and enables FP access before entry. This is reference-model behavior, not a hardware experiment here.
3. SPTM owns construction of the XNU monitor bootstrap arguments. Apple `start_sptm.s` expects x0 = boot reason, x1 = iBoot bootargs, x2 = SPTM bootargs; its cold path performs fixups and calls SPTM before C initialization. Supplying a guessed x2 structure is not a replacement for monitor initialization.
4. Runtime services remain necessary after entry. Apple `arm_init_sptm.c` registers exception-return handling, consumes monitor memory state, and initializes libsptm. One successful entry branch would not establish a functioning guest.

## Specific gaps in the available m1n1 branch

- `src/hv_asm.S:hv_enter_guest` enters EL1h. `src/hv_sprr.h` and Python `hv/sprr.py` model EL1/GL1 state. No complete virtual EL2/GL2 monitor environment was found in these paths.
- A synthetic instruction check of the actual patcher rewrites reads of SCTLR_EL1, TCR_EL1 and TTBR0_EL1. Reads of SCTLR_EL2, TCR_EL2, TTBR0_EL2, HCR_EL2 and CurrentEL remain unchanged and are absent from its virtual-register list. This checks the patcher, not execution of Apple instructions.
- `HV.load_macho` only applies the emulation hook to `__TEXT_EXEC`, not the actual Tahoe entry segment `__TEXT_BOOT_EXEC`. The branch still loads one payload and calls the old entry path; adding `-P` cannot establish monitor boot.
- No SPTM/TXM load arguments, combined monitor layout, monitor-first handoff, or proven monitor-to-kernel transition was found in this branch. PR #622 has extensible entry arguments but leaves the companion external.
- Existing guest-memory allocation and retained ADT monitor ranges need a new ownership/overlap audit. Old boot memory-map names cannot be treated as monitor runtime state.

The necessary unblock is the complete monitor-loading/virtualization implementation described by the upstream report, or new implementation and validation of that missing layer. Hardware execution of the old loader would not resolve these known missing initialization steps. No upstream message has been sent.

## Payload preparation completed

Test-group restore BuildManifest reports 26.6.2/25G83 and j613ap. Its `Ap,SecurePageTableMonitor` selects `Firmware/sptm.t8122.release.im4p`; `Ap,TrustedExecutionMonitor` selects `Firmware/txm.macosx.release.im4p`. Both copied files match their SHA-384 manifest digests. This is manifest consistency, not a new independent signature verification. Both extracted without decryption using PyIMG4 0.8.8. Proprietary images, manifest, checksums and extracted files remain outside Git under the local payload directory.

## Sources

- https://asahilinux.org/2026/08/progress-report-7-2/
- https://github.com/AsahiLinux/m1n1/tree/1c98fd09817cede0043d25c95fb540dbd683ef18
- https://github.com/AsahiLinux/m1n1/pull/622
- https://github.com/jprx/qemu-sptm/blob/6c3ca665bab9a08399f4681e4ada43bfcfb7d493/hw/arm/xnuboot_sptm.c
- https://github.com/jprx/qemu-sptm/blob/6c3ca665bab9a08399f4681e4ada43bfcfb7d493/hw/arm/darwin.c
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/sptm/start_sptm.s
- https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/arm64/sptm/arm_init_sptm.c
