# Free-run watchdog (2026-09-11)

`--free-run` now requires an explicit `--hang-budget` (integer seconds,
1..86400) in both the CLI and pipeline configuration. Budget timing starts at
`hv_start`, after upload. It includes callback handling time.

The existing m1n1 EL2 timer polls incoming proxy bytes in `hv_tick()`. At the
budget, the host sends the same single `!` byte as `HV.interrupt()`, from its
outer receive wait. The callback captures PC/registers and returns
`EXIT_GUEST` with `stop_reason: hang`. There is no writer thread, process kill,
or asynchronous signal performing USB I/O.

**HCR.FMO must be set.** The original hv_init defaults did not route physical
FIQs to EL2. The first synthetic native `b .` test timed out and required a
physical reboot. With FMO set, the same test stopped after two seconds at the
loop PC with `HV_EVENT.USER_INTERRUPT`, clean guest return, and proxy NOP.
This matches the routing described in Arm's
[virtualization guide](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Armv8-A%20virtualization.pdf).

Attempt 40 then exercised the watchdog in a real guarded run: after eret into
TXM, it recovered a native guarded vector loop at 120.39 seconds, with successful
cleanup and proxy NOP. Attempt 41's bounded TXM trace exited normally without a
kick. The installed m1n1 image was not changed; FMO is a per-run host HCR setting.

If no response arrives within budget + 15 seconds, the host abandons the receive
wait, saves `guest-unresponsive`, closes the host device, and **does no proxy
cleanup**. Every probe now tracks whether `hv_start` actually returned before
snapshot/teardown I/O. Callback transactions keep their original serial timeout;
the watchdog cannot recover arbitrary firmware/USB write stalls or broken EL2
timer delivery. It does not provide independent guest timer heartbeats or
same-PC sampling; it is a total-time bound using the existing EL2 timer path.

Synthetic hardware check (after the ordinary fresh gate, before real guarded use):

```sh
source setup/activate.sh
python scripts/free_run_watchdog_smoke.py --execute \
  --device ${M1N1DEVICE} --report /path/to/new-watchdog-report.json
```

Artifacts: `artifacts/runs/fresh-20260911-attempt40b/watchdog.json` (pass),
`artifacts/runs/fresh-20260911-attempt40/watchdog.json` (pre-FMO failure),
`artifacts/runs/observe-sprr/attempt-40/report.json` (guarded hang recovery).
