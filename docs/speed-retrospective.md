# Speed retrospective — how to do the same work faster

> Scope: an honest engineering retrospective for the target M3 SPTM
> monitor-virtualization research, reconstructed from `git log`, the observation
> arc (`docs/sptm-self-configuration-result.md`) and the real-memory phase
> (`docs/real-memory-phase-plan.md`, `docs/real-memory-stage0/`). The question
> being answered: **how could we have realistically reached the same results
> FASTER?** Speed is the constraint that makes the work sustainable, so the goal
> here is faster process, not blame. The science was sound; the serial cost was
> higher than it needed to be.

## The one number that matters

The work advanced almost entirely through **hardware "attempts"** (~17 of them),
and each attempt is a **serial, human-gated event**: a fresh-boot gate
(preserving chainload + transition/batch smoke + a 4096-step short probe), a
pipeline run (a batched 16 M-step run is ~6–8 min of guest execution — attempt-5
ran 11:58→12:06 UTC), and — whenever the device wedged or a run was killed
mid-USB — a **manual power cycle** that only the human in the loop can perform.
Everything else (offline analysis) is cheap and parallelizable. **Speed on this
project is almost exactly "how many hardware attempts did a result cost."** So
the whole retrospective reduces to one lever: *spend fewer hardware attempts to
reach each result, and make the ones you spend one-shot.*

## 1. Timeline of phases and attempts

### Phase A — Boot-data / live-TTBR baseline (pre-attempt records, 2026-09-09)
Reproduced the old fault (event 6,234,584 = RTBuddySeg wrapped-offset), wrote a
preserving chainloader, validated two live TTBR switches (the second installs a
13,834-leaf kernel map), and built the pipeline/catalog tooling. Established the
"records/stages, never applies" posture and the reusable probe.

### Phase B — Observation of self-configuration (attempts 1–9, 2026-09-09 → 09-10)
The monitor was driven from entry to the point where it needs real memory,
purely by observation. Each attempt bought one increment:

| Attempt | Cost | What it established |
|--------:|------|---------------------|
| 1 | run + Tailscale bundle transfer | Faulted on native `SPRR_PMPRR_EL1` (uncovered register) → offline fix |
| 2 | fresh-boot + run | `PMPRR` now stages; stopped on `SPRR_CONFIG=0xfb` (locks) |
| 3 | run | Stopped on `GXF_CONFIG=1` → guarded-world decision |
| 4 | run | Virtual guarded world entered; stopped on `AGTCNTRDIR_EL12` |
| 5 | fresh-boot + run (~8 min) | Full EL2-config staging; stopped on **unmapped IPA 0x211050218** (memory boundary) |
| 6 | run (`--back-page` 1 page) | +280 events; **mis-read as an SPRR permission divergence** |
| 7 | run (`--snapshot-leaf` + `--single-step-after`) | **Corrected attempt-6**: trigger was an undefined guarded instruction (`PMCR1_GL1`), not SPRR |
| 8 | fresh-boot + run (**first direct-USB, no relay**) | Stage `PMCR1_GL1`; +37 into a multi-page region fault |
| 9 | run (2 false starts first) | 16-page backing → scattered RMW regions; **declared the observation boundary** |

### Phase C — Stage 0 offline + R1 (attempts 10–11, 2026-09-10)
Four **parallel, read-only** offline analyses (region map, safe-DRAM range,
mutation/extent, SPRR model) from the attempt-4/9 bundles — no hardware. Then two
captures: attempt-10 (10 `--snapshot-leaf` VAs in **one** run, closed the SPRR
coverage gap, resolved 5/8 regions) and attempt-11 (backed A/B/C zeroed → **SPTM
completes full init and parks at a WFE idle loop**; D/E/F dormant, G/H already in
guest RAM). **R1 demonstrated.** This phase is the template for how fast the work
*can* go when analysis precedes hardware.

### Phase D — Real guarded execution (attempts 12–17, 2026-09-10)
Getting real SPRR/GXF actually enabled on the guest took ~5 hardware iterations:
13 = EL2 `u.msr` of the EL1 name (hit the HV's own copy under VHE); 14 = native
(EL1 SPRR gated by EL2, EC-0 undefined); 14–16 stalled at ~258 events; 17 =
EL12-alias redirect (`HV.MSR_REDIRECTS`) **plus** the EL2 SPRR/GXF context fix
(`u.msr(SPRR_CONFIG_EL1,1)`+`u.msr(GXF_CONFIG_EL1,1)` before the guest runs) →
**first real `genter` world switch** at event 7,786,859, then an immediate divert
to a spin at `0x100033f1a00`. Frontier: attempt-18 (batched) + capture the
guarded vector/bank state.

## 2. The biggest time sinks (evidence-based)

### Sink #1 — Iterating on hardware to discover a mechanism that was already in the reference source (attempts 12–17). **Confirmed, and the largest.**
Attempts 13→17 (≈5 hardware runs, each with a fresh-boot gate and at least one
power cycle) converged on: *apply the guest's SPRR/GXF via their EL12 aliases,
and establish the EL2 SPRR/GXF config context before the guest runs.* Both were
readable offline **before the first of those attempts**:

- The reference proxyclient `local/m1n1-vel2/proxyclient/m1n1/hv/__init__.py`
  defines `MSR_REDIRECTS` at **line 42**, and it already contains the exact map
  the attempts rediscovered: `SPRR_CONFIG_EL1→SPRR_CONFIG_EL12`,
  `SPRR_PPERM_EL1→SPRR_PPERM_EL12`, `SPRR_UPERM_EL0→SPRR_UPERM_EL02`,
  `GXF_CONFIG_EL1→GXF_CONFIG_EL12`, `GXF_ENTRY/PABENTRY`, `VBAR_GL1→VBAR_GL12`,
  `APCTL`, keys. `local/m1n1-vel2/src/hv_sprr.c` handles the
  `HV_VREG_SPRR_CONFIG_EL1` / `HV_VREG_GXF_CONFIG_EL1` config cases.
- These files are dated **2026-09-09** (hv_exc.c 15:01) — on disk a day *before*
  the 09-10 attempt-12→17 burn. `real-enable-mechanism.md` even says so in
  hindsight: *"the vel2 HV already redirects APCTL/KERNKEY this way … the alias
  redirect is the intended path."* attempt-17 says the context fix was done
  *"mirroring the vel2 HV."* We mirrored it — after paying for five runs to
  rediscover it.
- Bonus: the *open item* (`SPRR_PMPRR_EL1` and `*_SH{1,2,3}` have no EL12 alias)
  is visible by inspection of the same map — that too could have been known
  before hardware instead of after.

**Estimated cost:** ~3–4 avoidable hardware attempts (each = fresh-boot gate +
run + likely power cycle). Reading `hv_sprr.c` + `hv_exc.c` +
`__init__.py:MSR_REDIRECTS` offline first plausibly collapses 13→17 into **1–2**
runs (one to apply the alias+context path, one to confirm `genter`).

### Sink #2 — The `single_step_after=7786000` crawl. **Confirmed, and fully predictable.**
attempt-17 set `single_step_after=7786000`, so *everything* past 7.786 M ran
single-stepped at ~1 ms/step over USB. Execution reached the genter divert and
then spun for ~525 K events — all single-stepped — ≈ **15 min crawl**, killed
manually (device fine, but killed mid-USB → a power cycle to clear it). This was
predictable from the config alone: the genter is known to land near 7.79 M and
the run budget is 16 M, so an open-ended `single_step_after` at 7.786 M means
"single-step millions of steps." A one-line pre-flight lint (`single_step_after`
within a bounded window of the expected stop, not just below the budget) catches
it. **Cost:** ~15 min + a forced kill + a power cycle + the planned re-run
(attempt-18 exists specifically to redo this batched).

### Sink #3 — Operational false starts that burned runs. **Confirmed.**
attempt-9: *"Two operational false starts first: a loop variable shadowing the
guest `base` (fixed, 9020889) and a stale output dir the pipeline refuses to
reuse (removed)."* Both are pre-flight-catchable: the shadowing bug is a code
review / test gap on a brand-new `--back-page IPA:COUNT` path (the fix commit
9020889 is 2 lines); the stale-output-dir collision is an environment check. A
dry-run of a new flag against a captured bundle (offline, free) would have caught
the shadowing before spending the device. **Cost:** wasted setup cycles on a
serial resource plus attention at the worst time (device connected, one-owner).

### Sink #4 — Human-in-the-loop power cycles. **Confirmed, structural.**
Every wedge or manual kill needs a human power cycle, and every power cycle needs
a fresh-boot gate before the next run (observed at attempt-2, attempt-5,
attempt-8, and forced by attempt-17's kill). This is the dominant *latency*
(as opposed to compute) cost and it is unavoidable per-cycle — so the lever is to
**cause fewer cycles**: don't launch runs that will need a manual kill (Sink #2),
don't wedge on avoidable faults (Sinks #1, #3), and make the fresh-boot gate a
single automated command so the recovery itself isn't a manual multi-step
sequence.

### Sink #5 — Re-fetching large archives over Tailscale before the direct-USB switch. **Confirmed.**
Through attempt-7 the topology was target M3→USB host→(Tailscale/SSH)→analysis host: each run
produced a bundle that had to be transferred and imported — e.g. the verified
live-TTBR archive was **170,636,204 bytes** (171 MB) and a full run bundle was
**4.0 GB** moved off USB host. At **attempt-8** target M3 connected directly to analysis host
over USB: *"the pipeline runs locally — no USB host relay, no bundles or archive
transfers."* Every pre-8 attempt paid transfer + import latency that the direct
path eliminated in one move. **Cost:** per-run transfer/import overhead across
~7 attempts; recovered only once the topology changed.

### Sink #6 — Incremental one-dependency-at-a-time hardware chasing (attempts 6→9). **Found; partially avoidable.**
Attempts 6, 7, 8, 9 each advanced execution by a tiny increment (+280, +37, +27
events) by backing memory one page, then a page range, then discovering the
regions are scattered — four serial runs to learn the shape of the region set.
The offline **region-map analysis that made R1 a one-shot** (STAGE0 Wave 1:
"backing set is just A/B/C") was built from the *attempt-4/9 bundles* and could
have been done from the attempt-5 bundle **before** the incremental backing chase
— it enumerates the context pointer table (`x9+0x12f8`, `+0x1308`, …) statically.
Doing the map first plausibly collapses attempts 6–9 (four runs) into ~1–2.
**Cost:** ~2 avoidable runs.

### Sink #7 — A dirty (batched) syndrome drove a wrong interpretation. **Confirmed.**
attempt-6 concluded the stop was an SPRR read-divergence in the exception path;
attempt-7 (adding `--single-step-after` for a clean first-entry syndrome)
**disproved it** — the trigger was an undefined guarded instruction, and the
permission fault was a post-loop artifact. An entire run's interpretation had to
be corrected by a follow-up run. This is exactly the `MEMORY.md`
"clean-syndrome-before-interpreting" lesson, learned the expensive way. **Cost:**
the interpretation round-trip embedded in attempts 6→7.

## 3. Recommendations, prioritized by attempts saved

1. **Read the reference implementation offline before any hardware run whose
   purpose is "figure out how to configure X."** (Saves the most: ~3–4 runs on
   the SPRR/GXF case alone.) Concretely: before iterating on a mechanism, `grep`
   the vel2 source (`src/hv_*.c`) and proxyclient (`proxyclient/m1n1/hv/`) for the
   register/feature. `MSR_REDIRECTS`, the `HV_VREG_*` config handlers, and the
   trap paths are the map. Upstream is a *semantics reference* (consistent with
   `MEMORY.md` "no-cargo-cult"): you still build the minimal validated backend,
   but you read how the reference does it before spending the device to
   rediscover it.

2. **A pre-flight config lint + checklist, run before every launch.** One script,
   offline, free. It must flag: (a) `single_step_after` (or any single-step span)
   that isn't a bounded window around the expected stop — catches Sink #2; (b)
   a stale/pre-existing `--output` dir — catches half of Sink #3; (c) that
   one-owner + fresh-boot-gate status is green; (d) that all currently-known
   diagnostics are batched into this run (see #4). Estimated: eliminates the
   15-min crawl class, the false-start class, and the associated power cycles.

3. **Front-load offline bundle analysis so each hardware run is one-shot, not
   incremental.** Before backing memory or chasing a fault tail, statically map
   the region/pointer set from the last good bundle (the tooling — `translate`,
   `guest_pt`, snapshot decode — already exists). This is what made R1 a single
   run; applying it earlier collapses the attempt-6→9 chase. Estimated: ~2 runs.

4. **Batch every known diagnostic into each capture run — make it the default.**
   attempt-10 already proved this (10 `--snapshot-leaf` VAs + the SPRR-gap
   closure in one run). Rule: a capture run carries *all* currently-open
   snapshot-leaf / back-page / bank-capture targets, not just the next one. The
   attempt-17 open questions (`VBAR_GL1`, `GXF_ENTRY_EL1`, guarded bank) should
   all ride attempt-18, not spawn separate runs.

5. **Single-step the first-entry syndrome by default whenever a stop will drive a
   design decision.** Never interpret a batched syndrome (Sink #7 / `MEMORY.md`
   clean-syndrome rule). Cheap insurance against interpretation round-trips.

6. **Default to the lowest-latency transport (direct USB) from run 1.** The
   attempt-8 topology change (local pipeline, no relay, no 171 MB / 4 GB
   transfers) should be the starting configuration, not a mid-project discovery.

7. **Minimize human-gated power cycles by construction.** Don't launch runs that
   will need a manual kill (#2); reduce avoidable wedges (#1, #3); and reduce the
   *per-cycle* human cost by keeping the fresh-boot gate a single command with a
   clear pass/fail. The human is the serial bottleneck — spend that time only on
   cycles that actually advance a result.

## 4. What went well (keep doing this)

- **Offline analysis on captured bundles, in parallel.** Stage 0 Wave 1 — four
  independent read-only analyses run concurrently by subagents, zero hardware —
  produced the region map, safe-DRAM range, mutation model, and SPRR model that
  turned R1 into a single successful run. This is the fastest part of the whole
  project and should be the default mode; hardware should mostly *confirm* what
  offline analysis already predicted.
- **Flag-gated changes with a green suite throughout.** Every capability
  (`--back-page`, `--observe-sprr`, `--stage-el2-config`, `--real-guarded`,
  `--snapshot-leaf`) landed behind a flag with tests; the suite grew 211→248→
  317→323→325 and stayed green. The probe was never broken out from under a
  hardware session — no time lost to regressions.
- **The "records/stages, never applies" observation posture.** It safely drove
  the monitor to 7.786 M events with a clean HV exit every time, and it made most
  discoveries offline-analyzable after the fact.
- **Fresh-boot gate + one-owner discipline.** Across ~17 attempts the installed
  boot object stayed intact and boot-data integrity held — zero time lost to
  recovering a bricked/corrupted baseline, which would have dwarfed every sink
  above.
- **When batching/front-loading was applied (attempt-10, R1), it worked.** The
  project already contains the proof that the recommendations above are
  achievable — they just weren't yet the default.

---

# Retrospective 2 — SPTM boot-blocker chain → free-run (attempts 25–39, 2026-09-11)

13 hardware runs in ~2h50m cleared the whole SPTM boot-panic chain and built free-run.
Per-iteration cost flipped from "the run" to "the reboot cycle + analysis latency"
(floor ~2m49s with clean_reboot_target.py; free-run runs are ~30s).

## Biggest time sinks
1. **One-blocker-per-run in the DT/boot-parameter chain (runs 27–30).** Three of four
   panics were in ONE subsystem (chosen/hibernation: node -> strict key presence -> key
   size). Each fix read only the first consumer. A single pass enumerating ALL consumers
   + validations yields node+3 keys+3 sizes at once. The `sptm-boot-region-set` lesson
   ("enumerate all getter sites") was not generalized to the next named-input consumer.
2. **Free-run built late (runs 32–33, ~50 min).** After attempt-31 it was clear the bulk
   phases are millions of events; the response was to double the budget (attempt-33, 13
   min) instead of changing execution mode. Free-run was 54 lines and 25x faster. Rule:
   if a run ends on `instruction-budget` and the frontier is inside bulk work, do NOT
   re-run with a bigger budget — change the mode.
3. **Panic auto-stop built one run late (runs 27/28).** Both spun ~4.3M steps in the halt
   to budget; attempt-28's message needed a manual 9 GB stream scan. Add the terminal-
   condition auto-stop the moment its address is known.
4. **Free-run's collision with observation-mode guards found on hardware (34–36).** MDSCR.SS,
   TCR refusal, unhandled synthetic eret — all visible in the probe source. An offline
   audit of every `stop_reason` × {observe, real-guarded, free-run} plus a rewriter/handler
   consistency unit test would have replaced three runs.
5. **No hang detection in free-run (run 37).** 8-min hang; the kill landed mid-serial-write
   and teardown then touched a hung proxy -> dead device -> run 38 wasted.

## Wrong hypotheses / rework
- "WFE idle" was the panic halt (stood ~a day; launch-prep docs built on it; attempts
  24/25 called into a post-panic state). Name the enclosing function of any terminal loop
  before labelling it idle.
- "all 37 regions" claim missed SPTM-rm (reached via `mov x0,x23`) -> attempt-27. Cheaper
  cross-check: diff emitted names vs every region-name string literal in the binary.
- eret emulation built then reverted within 10 min, then the replacement (native) was also
  incomplete (patch_synthetic_code still rewrites eret to 0x4800) -> runs 36/37/39 on one
  instruction. Read the vel2 reference (hv/vel2.py, hv_exc.c) before the 3rd run on an
  instruction.
- Reboot helper "declared impossible" then found in the reference tree
  (proxyclient/tools/reboot.py). Check the reference tooling directory first.

## Forward-looking speedups (priority order)
1. **Hang watchdog for free-run (before the next run).** In-guest EL2 timer heartbeat that
   records PC and resumes; K same-PC ticks or a wall-clock budget -> `stop_reason: hang`,
   clean HV exit. Host wall-clock timeout LONGER than the in-guest one; teardown must NOT
   touch the proxy if the guest never returned (that killed the device in attempt-37).
   Make lint require a hang budget when free_run is set.
2. **Unattended reboot->gate->run chaining + a run queue** (stage configs A/B/C, walk away).
   Trim the gate for helper-driven reboots (skip the two smokes when m1n1.bin hash is
   unchanged).
3. **Apply-and-continue policy for probe over-restrictions under free-run** (staged regs,
   translation-control, known-safe transitions) so one run surfaces ALL of them.
4. **Auto-decode as a pipeline stage** (run decode_panic.py after every run; print a
   one-line "next action").
5. **Static input-consumer enumeration in lint** (regions, chosen/* nodes, DT keys+sizes,
   bootargs fields); fail pre-flight if the layout omits a required name. Extend to XNU's
   consumers after launch.
6. **Rewriter/handler consistency unit test** (every synthetic HVC imm the rewriter emits
   has a handler, per mode-flag combo).
7. Snapshot/restore NOT worth it now (SPTM boot is 27s in free-run; the per-boot SPRR/GXF
   lock is hardware state software can't restore anyway).

## What went well (keep)
clean_reboot_target.py (physical power cycle removed); free-run (25x); on-demand stage-2
(worked first try); the 7-region static-enumeration method; lint_config growing with real
footguns (extend with items 1/5/6).


# Retrospective 3 — verify the image before naming the milestone (2026-09-11)

The first resumed hardware test disproved the preceding handoff's XNU identity.
The eret bank read worked, but its value was TXM entry `0xfffffe0017070000`.
The old nonzero-target fallback executed TXM, then spun in a guarded vector;
the newly built watchdog recovered it. A live page-table walk and a 64-byte
payload comparison settled the identity cheaply. The producer disassembly also
names `TXM-entry` for global `0x98928`; `BootKC-entry` populates `0x98930`.

- Preserve the correct synthetic-tag finding, retract full SPTM boot/XNU launch.
  Similar epilogues and a shared constant are not enough to identify a consumer.
- HCR.FMO was the missing timer route. The first synthetic busy-loop required
  physical recovery; after enabling FMO, both the synthetic test and the real
  guarded hang returned cleanly. Test recovery before the expensive run.
- Replace address-range guesses with live mapping, loaded image identity, linked
  entry, and byte verification. Unknown targets stop. Distinguish a prepared
  entry from instructions executed after it.
- A bounded post-eret single-step window exposed TXM execution without repeating
  the full SPTM instruction trace. Keep this split for the next image transition.
- Run the full activated replay suite. Its factory had missed the new nonlocal
  MMU-validation state, free-run fields, and panic constants. Those defects were
  repaired, and non-free-run erets again retain their old observation-stop scope.

See [the launch correction](launch-prep/world-switch-is-the-launch.md) for the
retained evidence.


# Retrospective 4 — follow the native transition, not the earlier lookalike

The first TXM `eret` was only the start of the launch chain. The fastest route
past relocation was to fix the concrete VBAR bank mismatch, then resume only
the seven statically catalogued post-SVC `retab` sites with exact byte, mapping,
source-PC, PSTATE, and count bounds. That reached XNU in one 35-second run.

- The authentic first SVC immediately separated a firmware failure from a
  harness fault. `VBAR_GL1` had been staged while the live guarded bank retained
  the host vector. Redirecting it through `VBAR_GL12` fixed the original failure.
- An HVC software breakpoint was unsafe in this guarded routing and caused an
  artificial panic. Existing system-register traps gave enough observability;
  avoid inserting guest instructions when an adjacent trap already exists.
- Static callers do not predict dynamic service counts. Selector 3 had one
  direct caller but returned 42 times. A finite site allowlist plus reported
  per-site and global bounds preserved safety without one-run-per-return churn.
- The final XNU transition is native `gexit`, not either rewritten `eret`.
  Reading the exact trampoline resolved this before another hardware guess.
- Attempt 48's panic was useful positive evidence: its saved guest PC equals the
  XNU entry, proving transfer. Decoding `ESR 0x8600000f` also sets the next narrow
  frontier: execute permission on the entry leaf, before any instruction retires.
- Attempt 49 reused the trapped `ASPSR_GL1` write immediately before `gexit` and
  produced a clean, reproducible launch gate. The complete reboot, gate, and run
  cycle finished in about one minute; the probe itself took 35 seconds.


# Retrospective 5 — inspect return state before changing permissions

Attempt 48's entry PC was accompanied by an illegal-return PSTATE. Treating
that as a clean world switch overstated the evidence. The exact virtual EL2h
to physical EL1h normalization cleared the fault without touching permissions
and let XNU execute (attempt 51). Live entry table capture and guest permission
aliases made this test specific; the old snapshot path used stale shadows.

The first 4096 XNU steps remained in progressing Mach-O parsing. A larger
step budget would repeat the earlier bulk-work mistake. Native continuation
after a verified short prefix, stopping on the next probe exception with the
existing watchdog, became the feedback loop in attempts 53–56.

Early panic text travels through SPTM console calls before serial setup.
Decoding those calls automatically exposed each next failure immediately.
The pipeline now verifies the selected run archive and event count, preserves
the full console artifact, and prints a compact stop/cleanup/console summary.
This avoids rereading several megabytes of report JSON after every run.

A replay pass is not a semantic proof: the proposed AHCR shadow passed tests
but lacked defined hardware behavior. Reviewing the register contract before
the next hardware run prevented a misleading compatibility result.

Measured attempt 51–56 pipeline overhead was about 19–21 seconds beyond guest
execution. A 4096-step run took about 21 guest seconds, while native runs that
printed the early panic took about 41 seconds versus 16 seconds before that
console path. The trace has roughly 2800 monitor callbacks for 154 console
bytes. Replacing bulk stepping with native execution helped; future speed work
should measure callback costs rather than assume archive packaging dominates.

Attempt 58's early panic printed only part of its register dump. Reading the
saved-state VA and two header candidates through the unchanged guest tables
took about 0.15 seconds per capture and distinguished a wrong header pointer
from memory mutation. Preserve current guest RAM before an automatic reboot
when a panic names a useful saved-state address.

The AuxKC diagnosis also exposed an offline time sink: unnamed instruction
traces suggested several wrong caller/input interpretations before the installed
SDK structure identified the fields directly. Match captured structure size and
offsets to the applicable local SDK/public declarations early, then corroborate
with instructions. A valid Mach-O header is not automatically the right header:
the failing path was absent AuxKC initialization, unrelated to either BootKC
header. Finally, consult original iBoot sentinels before inventing empty-region
encodings; zero length did not make a nonzero address inert.

The AuxKC helper's first production invocation caught a local-import scope
error that helper-only tests missed. The first MMIO review caught the same
class of context dependency plus missing stage-2 TLB invalidation before any
hardware run. New callback paths should be exercised through the real stopped
handler and production dependency setup, with mapping/coherence order checked,
not just through a pure helper supplied with test-only dependencies.


# Retrospective 6 — distinguish a time limit from a stalled boot

Attempt 63 exhausted a 90-second watchdog while advancing through 362 distinct
SPTM MAP_PAGE calls in exact 16 KiB increments. Its final callback PC, selector,
and arguments established progress; the handoff observer's older PC did not.
An otherwise unchanged 180-second budget reached the next actual exception in
attempt 64 after 87.93 seconds. The watchdog's historical `hang` label alone
must not be interpreted as a native busy loop.

Compact reporting now includes the final retained event and activity counts,
separately from the handoff observer. Generic callback activity does not prove
forward progress; unique advancing page addresses supplied that evidence here.
The independent reviewer also caught that the observer updates on terminal
native exceptions, so its field must not always be labeled a prefix PC.

Measured persistence costs did not explain the long runtime. Attempt 63 wrote
roughly 175–180 MB of repeated reports, but local encoding and fsync timings
put their likely combined cost around one or two seconds. The 7,266 verified
SPTM callbacks dominate. Splitting durable journal checkpoints from less frequent
full snapshots is a possible future optimization; merely reducing journal
frequency would weaken crash evidence for little expected gain.

The architectural timer callback review caught a dynamic read-only status bit
that must be excluded from restoration equality. Production callback replay
then caught a missing namespace state variable before USB execution. Preserve
that separation: verify the register contract, exercise the actual callback,
and only then run hardware while independent source lookahead continues.


# Retrospective 7 — recover the first exception before changing the last trap

Attempt 67b ended at WFE, but emulating that instruction would have hidden the
failure. Saved guest exception registers pointed to an intentional debugger
break; two bounded saved-state/string captures recovered the earlier memcpy
permission fault. The explicit “invalid kernel stack” text was an early-boot
exception fallback, not proof that the stack had been corrupted.

The first independent analysis incorrectly treated an address outside the
kernel image as unmapped. A real archived page-table walk disproved that:
it was owned RAM with architectural write permission, further restricted by
SPRR. A final read-only SPRR value was also insufficient to prove the bank
state at the fault because panic handling had already run. Recording the
intended A-to-B-to-A window at its exact source sites gives causal evidence.

Callback-only tests missed a local variable shadowing the enclosing entry
instruction bytes. The full suite caught both entry-guard regressions before
USB. Fault injection then caught a separate cleanup problem: mark a register
as potentially modified before issuing its write, so readback failure cannot
silently skip restoration. Review helper behavior and its production state
transitions together.

Attempt 69 also confirms that a larger watchdog should be chosen from the
location of the proven frontier, not the total runtime alone. The same path
reached the permission window at about 145 seconds in attempt 68, so a
180-second budget leaves little time for the next page-map phase. Attempt 69's
terminal 123 maps advanced without repeats. A 360-second follow-up changes no
semantics while providing a full additional 180 seconds beyond the old total
budget. Preserve the exact event cadence when deciding whether another expiry
is progress or a loop.
