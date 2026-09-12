# Observation-only SPRR staging

The live-TTBR run `353b355f` stopped at SPTM's `SPRR_CONFIG_EL1 = 1` write
with monitor translation live, immediately after its TTBR1 root switch. The
public `hv-sprr` model answers that write by mirroring both guest roots into
shadow tables with per-index permission leaves; our audit shows that mapping
overgrants some pairs and ignores hierarchical attributes. Rather than port
it, `sptm_entry_probe.py --observe-sprr` (pipeline field `observe_sprr`)
continues without enforcing anything.

With the flag, any `SPRR_CONFIG_EL1` write is staged in the existing shadow
(attempt 2 showed SPTM locking it with `0xfb`: enable, config lock, permission
locks and three undocumented bits, all recorded per event). Without the
flag only untranslated writes of 0 or 1 are accepted. A translated write is
the existing shadow and recorded as `observed-sprr-config`, with the trace
index, value and the staged permission registers appended to
`report['sprr_observation']` (`enforced: false`). Reads return the shadow.
Any other value, `GXF_CONFIG_EL1` activation, `genter`/`gexit`/virtual
ERET and `GXF_STATUS_EL1` writes still stop. Without the flag the translated
activation remains `unsupported-el2-register`.

The first hardware attempt (run `d5dc52d5`) revealed that SPTM also writes
`SPRR_PMPRR_EL1` and the shareable permission mirrors `SPRR_UPERM_SH1..3_EL1`
and `SPRR_PPERM_SH1..3_EL1`, which the probe did not intercept; the native
`SPRR_PMPRR_EL1` write vectored the monitor into its own exception path, which
then looped on a data fault. All nine SPRR permission-configuration registers
are now staged as `staged-sprr-permission` and never reach hardware.

A static scan of the retained SPTM image (`msr`/`mrs` words in the Apple
`s3_6_c15` space) found 33 further registers the monitor programs that the
probe executed natively: the `*_EL12` aliases a monitor uses to configure the
level below it (SPRR, GXF, pointer-authentication keys, APCTL/APSTS, VM keys),
its own guarded level (`TPIDR_GL2`, read 248 times; `AFSR1_GL2`, `VBAR_GL12`,
`SP_GL12`) and three unnamed encodings. All are now listed once in
`APPLE_OBSERVED_REGISTERS` and staged; a test scans the payload and fails on
any uncovered access except `AFPCR_EL0` and `APSTS_EL1`, which already ran
natively without incident. This says nothing about whether staging is the
right semantics for a virtual EL2 monitor's lower-level aliases; it only
guarantees the accesses are recorded rather than faulting unobserved.

Independently of the flag, the guarded-world and range registers
`SPRR_AMRANGE_EL1`, `SPRR_UMPRR_EL1`, `GXF_ENTRY_EL1`, `GXF_PABENTRY_EL1`,
`VBAR_GL1`, `TPIDR_GL1`, `ASPSR_GL1`, `SPSR_GL1`, `ELR_GL1`, `ESR_GL1`,
`FAR_GL1`, `AFSR1_GL1` and `ASPSR_EL1` are now rewritten to HVC and staged in
a host dictionary (`staged-apple-register`, snapshot in
`report['staged_apple_registers']`); `GXF_STATUS_EL1` reads as zero. Their
values never reach hardware. Previously these encodings would have executed
natively at EL1 unobserved; no earlier run reached them.

What this shows: which registers the monitor programs after it believes
SPRR is on, and how far it runs before a guarded-world transition or a fault.
What it does not show: any permission enforcement, any fault SPRR would have
raised, or a guarded world. Pair it with `--stop-on-vector-entry` so an
exception the missing enforcement causes stops at the first recorded vector
visit instead of running the monitor's handler. The budget bound was raised
to 33,554,432 events because the previous run consumed 7.79M of 8.39M before
this point. Tests: `SprrObservationTests` in `tests/test_probe_controls.py`.
