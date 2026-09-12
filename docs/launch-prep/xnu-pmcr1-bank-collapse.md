# XNU PMCR1 EL12 bank collapse

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Under `--xnu-run`, the probe verifies a pinned adjacent instruction pair:

* linked `0xfffffe000b823a14`: `msr PMCR1_EL1, x17`
* linked `0xfffffe000b823a18`: `msr PMCR1_EL12, x17`

It rewrites only the second instruction to `msr PMCR1_EL1, x17`. The guest then
executes two identical native writes. There is no host register I/O and no
shadow PMU state.

Linux identifies `S3_1_C15_C7_2` as `PMCR1_EL12` and describes the EL1 and EL12
event filters as the two filters needed for guest-mode PMU events. The relevant
primary patch is Message-Id
`20241217212048.3709204-2-oliver.upton@linux.dev` (December 17, 2024).

This rewrite deliberately collapses the host and guest PMU filter banks because
the current bootstrap runs XNU at physical EL1 and does not support a nested
guest PMU. It does not claim nested PMU virtualization. Exact source words,
register `x17`, adjacency, and the `__TEXT_EXEC` site are checked before the
rewrite; source drift aborts the run.

## Hardware result

Attempt 58 (`1e6303f9-27a8-4e9c-b9d7-3eab89227d87`) progressed beyond
the PMU initialization and reported a data abort: `ESR_EL12=0x96000006`,
`ELR_EL12=0xfffffe002bfb4d94`, `FAR_EL12=0xfffffe00fd91e47f`. The faulting
instruction is a load in the boot Mach-O parser, not another system-register
access. Its early exception path printed an invalid-stack diagnostic; that
message alone does not establish corruption of the stack.

The 8405-event archive is finalized and verified. The guest returned, timer
state restoration was verified, and the proxy remained alive. This run retains
the explicit AHCR diagnostic suppression described in the AHCR audit. The
saved exception state at `0xfffffe002c563cb0` needs a bounded read before the
next reboot to identify the parser inputs.
