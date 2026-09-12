# attempt-17 — first real guarded execution (native genter worked) (2026-09-10)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

The EL2 SPRR/GXF context fix (`u.msr(SPRR_CONFIG_EL1,1)` + `u.msr(GXF_CONFIG_EL1,1)`
before the guest runs, mirroring the vel2 HV) was the missing piece. Config:
`--real-guarded` hybrid (native config/entry, EL12-mapped perms/APCTL/GL bank),
`single_step_after=7786000`.

## What happened

- **Advanced from ~258 events (attempts 14–16) to 7.786 M+** — the guest ran the
  entire early SPRR setup and the MMU/SPRR bring-up without the EC-0 faults that
  blocked every prior real-guarded attempt. The EL2 context fix works.
- **`genter` executed — a real world switch.** At event 7,786,859, PC
  `0xfffffe00070b0c20` (the `genter`) transferred to `0xfffffe00070b0b98` and
  SPSR flipped `0x600003c4 → 0x604013c5` (bit `0x400000` set = guarded world).
  This is the first time the monitor really entered the guarded world under the
  probe — not the virtualized model, the real instruction.
- **Then it diverted to a spin.** One step later (event 7,786,861) PC jumped to
  physical `0x100033f1a00` and stayed there for the remaining ~525 K events (a
  single-PC self-loop, `b .`). `0x100033f1a00 = RAM_base 0x10000000000 + 0x33f1a00`,
  which is **below the isolated guest window** (`guest_base 0x1000e000000`) — in
  the m1n1/boot region. SPSR was unchanged across the jump, so it is not a fresh
  EL-exception; likely a guarded-world exception vectoring through `VBAR_GL1`, or a
  jump to a stale/parked address.
- **The run crawled** because `single_step_after=7786000` single-steps everything
  past 7.786 M at ~1 ms/step over USB; 525 K steps ≈ 15 min. It was stopped
  manually (device fine; killed mid-USB, so a power cycle clears it).

> **Divert decoded (source-grounded):** the post-genter spin is analyzed in
> [attempt-17-divert-analysis.md](attempt-17-divert-analysis.md), which combines
> this trace with the vel2 GXF source: `genter` is a fixed-pointer transfer (so the
> divert is a *second* event — the `msr` faulted), and a same-EL guarded sync
> exception vectors to `VBAR_GL1 + 0x200`. Prediction: `VBAR_GL1 == 0x100033f1800`.

## Reading

`genter` working is the milestone the whole real-memory phase was aiming at. The
immediate divert to a spin below the guest window is the next question:

- The guarded world uses its own vector base `VBAR_GL1` and exception banks. If
  `VBAR_GL1` (native now, not recorded) points into the m1n1/boot region, a
  guarded exception right after entry would vector to `0x100033f1a00`. The
  instruction at `0xb0b98` was `msr S3_6_C15_C11_1, x0` (guarded per-CPU base);
  if it or the next guarded access faulted, it would vector via `VBAR_GL1`.
- Alternatively the guarded entry target/`VBAR_GL1` was never set to a real
  handler under the probe, so it lands on whatever is at `0x33f1a00` (a spin).

## Full-trace-pass confirmation (offline, 2026-09-10)

A single streaming pass over the 8,311,802-event trace
(`artifacts/runs/observe-sprr/attempt-17/runs/da67557c-…/events.jsonl`, 4.6 GB)
pins the facts:

- **Exactly one** normal→guarded transition, at index **7,786,860**, landing at
  guest VA **`0xfffffe00070b0b98`** (SPSR `0x600003c4 → 0x604013c5`, guarded bit
  `0x400000` set). This is the first and only real guarded entry.
- **The guarded-call dispatcher `0xfffffe00070a4524` was never reached (0 hits).**
  So this entry is *not* a type-0 service call to the dispatcher — it is the
  monitor entering the guarded world during its own per-CPU bring-up, landing in
  an init path at `0xb0b98`.
- The single guarded instruction at `0xb0b98`
  (`msr S3_6_C15_C11_1, x0`, a guarded per-CPU base write) **does not retire to
  `0xb0b9c`**: PC leaves for physical **`0x100033f1a00`** at index 7,786,861 and
  stays there — **524,941** identical events to end of trace. A far jump instead
  of `+4` means that guarded write **faulted and vectored**, not branched.
- Exit syndrome on the spin (EL2 view): `ESR 0xca000022`, `FAR 0x0`, `SPSR
  0x604013c5` (guarded retained). `FAR 0` argues against a data-address abort;
  the low bits of the ESR (`0x…22`) are consistent with a guarded exception. The
  authoritative cause needs the guarded bank (`ESR_GL1`/`ELR_GL1`), captured by
  the exit snapshot in attempt-18.

Reading: a genuine guarded exception on the first guarded register write, vectored
through the guarded vector base. If `VBAR_GL1` (from the attempt-18 snapshot)
equals `0x100033f1a00` minus a fixed vector offset, that is confirmed.

## Next steps (offline-prepared)

1. **Batched re-run (attempt-18, staged):** `single_step_after=0` so it reaches
   the divert in ~6 min instead of crawling, confirming the guarded-entry → spin
   path at speed and giving a batched trace to 16 M.
2. **Record the guarded vector/entry state.** Capture `VBAR_GL1`, `GXF_ENTRY_EL1`,
   and the guarded exception bank at the enter point to determine whether
   `0x100033f1a00` is `VBAR_GL1` (a guarded exception) or a jump target. This may
   need a small probe addition (snapshot the guarded bank at the genter), since
   those registers are native (untrapped) in `--real-guarded`.
3. **Single-step only a bounded window** around the genter (tooling below) so the
   transition is captured cleanly without single-stepping the subsequent spin.
