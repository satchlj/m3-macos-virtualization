# Multi-call run — ready-to-go runbook (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Everything is built and validated offline. When target M3 is power-cycled, this is the
exact sequence for the first multi-call guarded run (attempt-24).

## Build status (all committed, suite green 321)

- `--guarded-call-selectors HEX[,HEX...]` (probe): issues one real guarded call per
  selector in ONE run via the idle->genter loop; sets x16 per call, captures x0;
  records `report['guarded_calls']`. MUTATING (the C service runs). Commit a29dda7.
- ABI confirmed live (attempt-23): genter -> dispatcher 0xa4524 -> type-0 -> T0.
- Pipeline field + validation + lint; replay updated.

## Pre-flight (fresh boot required)

1. The owner power-cycles the target M3 and boots m1n1 from the dedicated test installation.
2. `bash artifacts/fresh-gate-local.sh` (chainload once) -- must pass (exit 0).
   Do NOT re-gate afterward (re-chainload over a used m1n1 hangs).
3. Confirm the attempt-24 config is lint-clean.

## attempt-24 config (FINALIZED, staged, lint-clean)

`artifacts/runs/observe-sprr/attempt-24.config.json`: attempt-23's config minus
`first_contact`, plus:
- `guarded_call_selectors` = `0x100000000,0x200000000,0x300000000,0x400000000,0x500000000`
  -- a sweep of CALL_SPTM (event 2, the SAFE family) func indices 1..5
  (x16 = idx<<32). Each call returns a status OR halts cleanly at the panic path.
- `single_step_window` = `7810000:150000` (idle + several call iterations).
- keeps real_guarded, stage_el2_config, back_page A/B/C, stop_on_guarded_vector.

Why this is safe (see service-selector-map.md): CALL_SPTM never `eret`s to another
domain and does no inline PT/SPRR/GXF mutation. An invalid func index LOG+PANICs
(non-mutating, non-launching); the probe HALTS at the panic (0xf8ca0) before it runs
(`stop_reason guarded-call-panic`). So the sweep is non-mutating either way. It does
NOT include ENTER_GUEST (0x1b, kernel launch) or CALL_TXM/SK (secure domains).

Run it: `bash artifacts/runs/observe-sprr/attempt-24.sh` (after the fresh gate).

## One-run-per-boot rule

This is a real-guarded run: ONE per boot. A 2nd hv_start crashes (SPTM locks
SPRR/GXF). The whole point of multi-call is to do many calls IN this one run, so pick
the full selector list up front.

## Reversibility (MUTATING run)

The service executes, so this can change monitor state. Before running: start with
the SAFEST (read-only/query) selector from the map; keep the list short; confirm the
installed boot survives (chainload_preserve_boot) after. Do NOT include a selector
classified mutating/launch until the query round-trip is understood.

## Decode after

`report['guarded_calls']` = [{index, selector, result, steps}] -- the result (x0)
each call returned via gexit. Compare results to the selector-map predictions; this
is the first observation of real SPTM service behavior.
