# VBAR_GL1 redirect audit (attempts 18–42)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

## Finding

> Hardware result: attempts 45–49 applied both writes through `VBAR_GL12`,
> verified exact readback, routed TXM's authentic SVC into SPTM, and continued
> through the XNU launch. The proposed bounded correction is validated.

`VBAR_GL1` belongs in `real_redirect`. This is not a speculative new
mapping: the local vel2 proxyclient already defines
`VBAR_GL1 -> VBAR_GL12` in `HV.MSR_REDIRECTS`. The probe currently patches the
guest write but leaves it in `apple_shadow`, so SPTM reads its requested value
back if it asks while hardware keeps m1n1's run-relocated guarded vector.

The minimum hardware change was `VBAR_GL1` alone. `FAR_GL1` is a sensible
follow-up for faithful exception-state capture, but its GL12 alias is not in
`HV.MSR_REDIRECTS` today and it is not needed to select the correct SVC vector.
`AFSR1_GL1` has the same alias pattern but no observed use before the failure.

## Expected values and route

Attempts 20–42 consistently record two SPTM writes:

| original MSR PC | reported HVC return PC | value | role |
| --- | --- | --- | --- |
| `0xfffffe00070b0be4` | `0xfffffe00070b0be8` | `0xfffffe00070ad000` | early guarded vector |
| `0xfffffe00070b0c54` | `0xfffffe00070b0c58` | `0xfffffe00070a8000` | final vector used for the TXM call |

The event records contain the HVC exception link, which is the instruction
after the rewritten MSR. The original words at the two sites are respectively
`msr VBAR_GL1, x0` and `msr VBAR_GL1, x2`.

The second value must therefore be present in the hardware guest guarded bank
at TXM's first `svc #0`. The expected lower-world synchronous entry is
`VBAR_GL1 + 0x400 = 0xfffffe00070a8400`; that slot branches to SPTM's handler at
`0xfffffe00070a5e28`, which recognizes SVC64 (`EC=0x15`) and immediate zero.

Instead, exit snapshots read a different physical-looking m1n1 address through
the live alias on every run (for example attempt 40: `0x10003611800`; attempt
42: `0x10003731800`). The address varies with m1n1 relocation while the staged
SPTM value is stable. Attempts 18–19 also proved the consequence: a guarded
exception went to the stale base plus `0x200` and recursively instruction-
aborted. Attempt 40 ended in the same signature after the TXM handoff.

## Source contract

- `proxyclient/m1n1/hv/__init__.py` includes
  `VBAR_GL1: VBAR_GL12` beside the SPSR/ASPSR/ESR/ELR redirects already used by
  the probe. Its generic trapped-MSR path writes the mapped alias.
- `src/hv_sprr.c` gives virtualized `HV_VREG_VBAR_GL1` the same banked meaning:
  update the live lower guarded vector while guarded, otherwise update the
  saved guarded bank. Its `GL1_BANKED` cases similarly route SPSR, ELR, ESR,
  FAR, and AFSR to the lower guest bank.
- `src/hv.c` sets m1n1's own `VBAR_GL1` before `hv_start`; this explains the
  stale run-relocated value, but does not make it a valid guest vector after
  SPTM replaces it.
- The probe already obtains valid TXM `ELR_GL1`/`SPSR_GL1` values through the
  same `_GL12` mechanism, so this is an exercised access path, not just a name
  match.

There is a minor source asymmetry: C `hv_exc.c` does not list a direct
`VBAR_GL1` `SYSREG_MAP`, while the Python `HV.MSR_REDIRECTS` table does. That C
switch is not the probe's mechanism; the probe explicitly handles its HVC tag
and calls `u.msr(HV.MSR_REDIRECTS[reg], value)`. The independent
`hv_sprr.c` banked implementation supports the Python table's semantics.

## FAR and AFSR

`FAR_GL12` and `AFSR1_GL12` exist in the Apple register description, and
`hv_sprr.c` maps virtualized `FAR_GL1`/`AFSR1_GL1` to the guest's
`FAR_EL12`/`AFSR1_EL12` state. Thus directing the real guarded variants to
their corresponding GL12 aliases is architecturally consistent. However:

- neither alias is currently present in `HV.MSR_REDIRECTS`, so merely adding
  the GL1 names to `real_redirect` would raise a lookup error;
- no `FAR_GL1` or `AFSR1_GL1` guest access is recorded before the attempts
  18–42 terminal fault;
- once the correct vector runs, SPTM does read `FAR_GL1` while saving the
  exception frame. Returning the current zero shadow is harmless for an SVC
  dispatch but loses diagnostic fidelity for an actual abort;
- no current evidence makes `AFSR1_GL1` part of SVC dispatch.

Therefore use `VBAR_GL1` as the bounded first correction. Add an explicit,
tested `FAR_GL1 -> FAR_GL12` mapping when preserving real fault state becomes
necessary; add AFSR only with the same test or an observed consumer.

## Risks and hardware gate

The intended write is to the guest lower guarded bank through `VBAR_GL12`, not
to the hypervisor's current `VBAR_GL1`, so it should not replace the host's own
exception vector. Remaining risks are undocumented Apple alias semantics and a
bad guest vector mapping/permission causing another recursive abort. Bound the
first run with the existing watchdog and stop immediately at the first post-SVC
vector. Success criteria are a live `VBAR_GL1` readback of
`0xfffffe00070a8000` and control at `0xfffffe00070a8400` (then
`0xfffffe00070a5e28`), before making any claim about the SVC service or XNU.
