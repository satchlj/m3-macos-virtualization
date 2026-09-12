# Multi-call reversibility — safety plan for the first mutating guarded call (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

`--first-contact` was non-mutating (halted at 0xa4ac0 before the service). The
multi-call driver (`--guarded-call-selectors`) lets the C service RUN, so it is the
first time a real SPTM service executes under the probe. This plans the safety.

## What can and cannot be mutated

- **Transient / per-boot (safe-ish):** SPRR/GXF/guarded hardware state, guest RAM,
  SPTM's managed structures in the backed regions (A/B/C) and RAM. All cleared by a
  power cycle; do not touch the installed boot object (on disk) or persistent secure
  state by themselves.
- **Dangerous (must avoid until understood):** anything that writes PERSISTENT or
  SECURE state — SEP, fuses, CTRR-locked regions, disk/NVRAM — or that LAUNCHES the
  kernel (`EVENT_ENTER_GUEST`). A launch would start a whole normal world below SPTM,
  far beyond a bounded observation.

## Selector policy for the first multi-call

- Issue ONLY the event the service selector-map classifies as SAFE (state-only /
  returns a status, no mutation, gexits) — from
  [service-selector-map.md](service-selector-map.md) once the transition decode is
  complete. Start with exactly ONE such selector, then a short list.
- Do NOT include `EVENT_ENTER_GUEST` / `EVENT_EXIT_GUEST` (world launch/switch) or
  any event classified MUTATING/LAUNCH in the first run.

## Reversibility checks (before and after)

Before:
- Fresh-boot gate passed (installed boot preserved by chainload_preserve_boot).
- Bounded: a short selector list; single-step coverage so the HV keeps control.
- Confirm the safe selector's action reads/returns and gexits (from the map).

After the run:
- `report['guarded_calls']` populated with results; proxy alive; clean exit.
- Confirm the installed boot survives: the run does not chainload again, and a
  power-cycle + picker boot returns to a working m1n1/macOS (the normal recovery).
- If anything unexpected mutates (an unexpected stop, a fault, a reboot), treat the
  run as the reversibility test itself: the installed boot object on disk is
  untouched by RAM-only guarded activity, and a power cycle restores a clean state.

## Escalation

If the safe selector's service turns out to mutate more than expected (observed in
the single-step trace before it commits), the bounded step budget + single-step let
us halt. The worst realistic outcome remains a power-cycle-recoverable RAM state, not
persistent damage — provided we exclude ENTER_GUEST and secure-monitor calls
(TXM/SK) until their effects are mapped.
