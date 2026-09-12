# Opt-in TPIDR_GL2 firmware fast shadow

`--xnu-tpidr-gl2-fast-shadow` is a narrow performance experiment for the
existing `TPIDR_GL2` trap-and-host-shadow model. It requires `--xnu-run` and a
pinned m1n1 runtime exposing these proxy methods:

- `hv_vel2_tpidr_gl2_shadow_enable(tag_base, initial_value)`
- `hv_vel2_tpidr_gl2_shadow_status()`
- `hv_vel2_tpidr_gl2_shadow_disable()`

The status schema is exact: `enabled`, `tag_base`, `shadow`, `reads`, `writes`,
and `forwarded`. Missing methods, malformed status, nonzero counters at enable,
or an enable readback mismatch stop the run without releasing XNU into native
execution. An ambiguous enable failure also triggers an independent disable
attempt.

The host derives the tag from the actual sorted `extra_regs` table used to
rewrite the pinned SPTM image:

```
0x8000 | (extra_regs.index(TPIDR_GL2) << 6)
```

This is provenance, not a separately pinned magic number. The low six bits are
reserved for the read bit and register number. Firmware validates that the
masked tag remains in the custom `0x8000` HVC family.

## Activation and teardown gates

Preflight queries firmware and proves the fast shadow is disabled before guest
execution. It clears and verifies any stale enabled state. The ordinary host
`apple_shadow` continues to service `TPIDR_GL2` during SPTM initialization and
the bounded XNU prefix.

Activation occurs only after all of these existing checks pass:

1. the native XNU handoff has reached and retired beyond its verified entry;
2. `classify_entry` identifies the continuation as `kernelcache`;
3. the continuation bytes match the pinned input;
4. firmware accepts the computed tag and the current host-shadow value; and
5. status readback proves the exact tag/value, enabled state, and zero counters.

Only then does the probe set `handoff_state.native`, clear single-step, update
the saved context, and reply `HANDLED`.

When `hv_start` returns, the host first captures status and counters, copies the
firmware `shadow` value back into the original host shadow, and then disables
the fast path with readback. Audit failure cannot suppress the disable attempt.
If `hv_start` does not return, the existing safety rule forbids further proxy
I/O because target state is unknown; the report marks fast-shadow teardown as
skipped rather than claiming disable.

## Limits

This path handles only the exact rewritten `TPIDR_GL2` tag. Other custom HVCs
continue through the ordinary host callback and increment `forwarded` while the
fast path is enabled. It does not make native GL2 register access valid, model
other Apple registers, enforce SPRR permissions, or establish a macOS boot.
The firmware state and counters are CPU-local; current evidence covers the
single CPU running the probe, not a multiprocessor guest. Counter totals are an
audit of routing, not proof of higher-level XNU progress.

## Hardware validation — attempts 72 and 73

Attempt 72 (`499e54e9-3a51-40e6-ad23-3bff9eb9b562`) activated tag `0xb0c0`
only after the verified XNU continuation. Firmware handled 14,038 reads and no
writes, forwarded 7,991 other HVCs, and preserved the exact shadow value
`0xfffffe0007106200`. It reached 894 selector-2 map calls and a new MDSCR_EL1
read in 39.28 seconds. By comparison, the non-fast attempts 69, 70, and 71
recorded 620, 650, and 658 map calls in 180.28, 360.33, and 900.50 seconds.
ASLR and differing terminal phases prevent treating those ratios as a precise
microbenchmark, but the operational feedback loop improved from watchdog-bound
minutes to a real new stop in under 40 seconds.

The new read was `MRS MDSCR_EL1, x10` at SPTM PC
`0xfffffe00070a4094`. The same persistent disabled-debug shadow had already
served the structurally identical block before native handoff and held the
TDCC-only value `0x1000`. Post-handoff routing now reuses that model, advances
the saved PC without setting single-step, and never accesses physical MDSCR.
Unknown system registers and unsupported debug values remain fail-closed.

Attempt 73 (`32404334-e228-48ff-b841-ff03b4080123`) hardware-validated that
continuation. It passed the read and following TDCC-only write, handled 14,125
fast reads, forwarded 8,049 HVCs, and reached the next guarded ERET frontier in
50.03 seconds after 896 selector-2 maps. The ERET at SPTM PC
`0xfffffe00070a410c` names target `0xfffffe001703103c`, target SPSR `0x13c0`;
the current image classifier stops it as `eret-unclassified-target`.

Saved-table analysis resolves that target through TTBR1
`0x10015060000` to PA `0x1000fea903c`, TXM `__TEXT_EXEC`, linked PC
`0xfffffff01703103c`. The first 32 source bytes match the pinned TXM exactly:
`1f000091007e40921f0000f160f6ff54e803009108354092880000b4a0feffb0`.
The stop is therefore a finite-policy boundary, not an unknown mapping: this is
neither the TXM entry nor an existing ret-prefixed return-catalog site. Any
continuation must use a new opt-in exact-site gate and bounded stepping rather
than broad acceptance of TXM interior targets.

The exact 32-byte target SHA-256 is
`cef67431c02543f1848194725aa1a71be428f35c07ac64d7c7754c488faff4a8`.
Disassembly begins `mov sp,x0`; attempt 73 has aligned x0
`0xfffffdf000188000`, and saved tables map its prospective stack page writable
and owned. The safest next experiment is therefore one instruction only,
expecting PC `0xfffffe0017031040` and SP equal to x0 before considering any
larger continuation window.

Both runs completed two exact PPERM A-B-B-A windows, left physical PPERM
untouched, returned the guest cleanly, synchronized the host shadow, disabled
the firmware path with readback, and left the proxy alive without cleanup
errors. Full macOS boot is not established.

Attempt-72 event SHA-256 is
`6507e1d02a828afb39a1271f74d68b1ae9844e76fba3d652356b3c1e7591fa05`;
archive SHA-256 is
`d566494b2af54b7792321d594db0c61100bd4cb79aab54b81d19143ca46886f4`.
Attempt-73 event SHA-256 is
`cd123698e53cbdffde423a9781baed3e9115f589e29dc2ad1cdf858798221aad`;
archive SHA-256 is
`651e44f79303fe08466c0d5095110d3de2363b351cc0ccf433275d154c954daa`.
