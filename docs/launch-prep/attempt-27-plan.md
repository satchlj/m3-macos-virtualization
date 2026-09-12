# attempt-27 — clean real-guarded boot with the full region set

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

## What changed since attempt-25
attempt-25 reached the SPTM boot panic halt (0xf8b88) at step ~7.8M, but
because it had patched that halt to `genter` (first-contact) and injected an
ENTER_GUEST (x16=0x1b) call, it recorded a *nested* `guarded-call-panic`
rather than a clean panic. The clean root cause came from static analysis.

Enumerating every `init_get_image_region` call site (getter 0xbcc98; 65 sites;
32 distinct required region names, all passing required=1) against what
`sptm_layout.py` emitted showed **seven required regions were missing**:

    slide, CL4-entry, CL4-virt, CL4-rw, CL4-le, AuxKC-rw, AuxKC-le

`slide` (looked up at 0xbefac) is the first miss; the per-image entry-PC routine
at 0xbf000 looks up CL4-entry/CL4-virt straight-line right after it, so `slide`
alone would not have cleared the boot. Commit 4c013ec adds all seven.

Region semantics (all from the consumers, offline):
- `slide`: its paddr is copied verbatim into the XNU boot handoff as the kernel
  KASLR slide (global 0x98988 -> handoff [x19+160] at 0xe0a70). We place every
  image at its linked address with no randomization, so the slide is **0**.
  Emitted as a raw (0,0) property (a normal paddr region would encode
  base+offset and be misread as a huge slide).
- `CL4-entry`/`CL4-virt`: VA pseudo-regions read only while computing the
  (absent) cryptex collection's entry PC; never entered on the XNU path. Zero.
- `CL4-rw/le`, `AuxKC-rw/le`: empty size-0 image regions (standard "absent").

The getter's `type == 16` gate is the memory-map property **length** (the
classic {u64 paddr; u64 size} = 16 bytes); our tuples already satisfy it.

## The run
attempt-27 is a **clean** real-guarded boot: attempt-25's proven flag set minus
`guarded_call_selectors` and `single_step_window`. Crucially it does NOT patch
0xf8b88, so a residual panic halts at the real panic entry 0xf8ca0 and the probe
records `report['sptm_panic']` with clean args (`stop_reason: sptm-panic`).

Real-guarded is one-shot per boot (locked SPRR/GXF), so this run is precious.
It batches (step_batch 256) straight to the terminal; the always-on panic and
launch-xnu-entry stops report where boot now ends.

## Decision tree on the result
1. **stop_reason == sptm-panic** (halt at 0xf8ca0): a region is still missing or
   mis-valued. The panic args carry the failing region name / format string.
   Read `report['sptm_panic']` (pc, lr, args, prior_pcs), map lr into the getter
   caller, add/fix that region offline, re-stage. (No hardware cost beyond this
   run; next run needs a power cycle.)
2. **stop_reason == launch-xnu-entry** (PC in [0xbfb0000, 0xc800000)): SPTM
   completed boot and self-launched XNU. Milestone. Capture `report['launch']`
   (entry PC, x0=boot_args ptr, SPSR) and move to first-XNU-instruction tracing.
3. **runs to step budget** (16.77M) with PC deep in SPTM code, no panic: boot
   completed but does not self-launch; it is sitting in a normal-world loop
   (gexit/idle) waiting for an external ENTER_GUEST. Next run injects a single
   ENTER_GUEST guarded call at that loop PC (not 0xf8b88, which is the panic
   halt) — identify the loop PC from the final trace and use a targeted
   genter-injection at that address.

## Prereqs to run
- target M3 power-cycled to a fresh m1n1 (real-guarded is one-shot; it is currently
  spent from attempt-25). Fresh-boot gate first, then `bash
  artifacts/runs/observe-sprr/attempt-27.sh`.
