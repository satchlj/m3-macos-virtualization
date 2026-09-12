# Guest boot first: evidence and next experiment

> Historical research context. Status and proposed next steps below describe the
> original investigation. See [current project status](STATUS.md) for later
> results and remaining milestones.

Baseline: m1n1 commit in `upstream.lock`. Official guest support currently includes Sonoma 14.8.3 for M1–M3, not a general guarantee for modern Tahoe. A local port need not use that baseline, but support cannot be established by a version alias.

## Findings grounded in public source

- `hv/__init__.py:load_raw` unconditionally reads `SEPFW` and `TrustCache` before loading. Missing entries are a definite input failure.
- The unpatched baseline writes bootargs for revision <=1, 2 or 3 only, without a final rejection. Before the included patch, revision >3 could leave the guest bootargs unwritten. Preflight conservatively rejects revision 0 as well. This is a potential failure mode, not a claim Tahoe uses revision 4.
- `tgtypes.py` defines three ASCII command-line fields. Preflight reserves a NUL byte, a conservative contract beyond Construct's padded-field acceptance.
- The unpatched `run_guest.py -C` iterates characters, forming `cpuN` for each; multi-digit CPU names cannot safely use that syntax. The actual boot CPU must be retained. CPU selection happens after `hv.init`, so a single-core guest does not isolate failures inside hypervisor initialization itself.
- Firmware map failure returns None; no general Sonoma-only loader allowlist found. Correct classification/diagnostics can be added without pretending an old ABI matches.
- Public Apple XNU `pexpert/pexpert/arm/boot.h` main defines revision/version fields and revision 1/2 macros; this generic public header is not tied to the exact Tahoe build and does not override observed m1n1 revision 3 support. A public header alone is insufficient evidence for the shipping boot ABI.
- Existing M3 CPU counter initialization and secondary-core MMU fixes are already in the pinned checkout. Avoid diagnosing from obsolete failure reports. Loader exception/instruction adaptation exists, but no proprietary binary analysis was used here.

## Proposed hardware experiment (not authorized or performed)

1. Review and separately authorize a dedicated same-version Tahoe test OS volume group and its own recovery/boot-policy setup. Keep the daily system's boot object untouched. Backup and reversibility plan required; adding an OS is not assumed firmware-neutral.
2. Establish plain m1n1 proxy first. Record minimal bootargs revision/version, exact firmware string, memory-map names, actual boot CPU, CPU feature state and matching build identity. If this fails, a guest decoder is not the first blocker.
3. Run this offline preflight. Resolve blockers; unknowns remain experimental, not permission to proceed.
4. Use the included public loader stage markers to distinguish hypervisor-init, image/bootargs serialization, entry transition and first exception. Run a matching untraced guest retaining only the actual boot CPU. No GPU modules; no destructive devices/commands. Capture stage tags and first fault register metadata, not disassembly.
5. Interpret: failure before entry points to host-loader/init/boot contract; first guest fault points to entry/CPU/monitor/exception contract; first serial output is only early progress. Repeatability precedes multicore. Compare multicore only after the single-core baseline; GPU work comes later.

SPTM/TXM is an architectural question, not a proven version-check problem. Apple's platform-security documentation describes M2+ support; exact guest boot mode requires evidence. A successful synthetic test never proves this contract or feasibility of a full Tahoe port.

Sources:
- https://asahilinux.org/docs/sw/m1n1-hypervisor/
- https://github.com/AsahiLinux/m1n1/tree/940439b9a407fbfc499bea933269219f3f62d4c7
- https://github.com/AsahiLinux/m1n1/pull/613
- https://github.com/apple-oss-distributions/xnu/blob/main/pexpert/pexpert/arm/boot.h
- https://support.apple.com/guide/security/sec8b776536b/web
