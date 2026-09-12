# Upstream reuse audit — September 9, 2026

Tahoe remains the first target. Upstream provides useful capture and loader machinery, but this audit found no ready replacement for our missing Tahoe monitor integration or a ready M3/Tahoe GPU ABI decoder. The immediate reuse opportunity is to put existing capture patterns behind reproducible experiments and preserve raw evidence for later decoding.

## What was checked

An isolated bare mirror of AsahiLinux/m1n1 was used so neither pinned working checkout was modified. [The machine-readable snapshot](upstream-audit-2026-09-09.json) records full hashes and advertised branches. Inspection covered main, hv-sprr, gxf-stack, lina/gpu-wip, and PR 622; this is not an exhaustive audit of all forks or unpublished work.

| Candidate | Finding | Action |
| --- | --- | --- |
| main, `940439b9` | Exactly our loader pin | No repin needed |
| hv-sprr, `1c98fd09` | Exactly our experimental pin; SPRR/GXF emulation already sourced | Integrate with our vEL2 runtime; updating the branch does not resolve their runtime conflict |
| Firmware 14.8.3, `580952dd` | Already included: `iBoot-10151.140.19.700.2` maps to `V14_7` | Keep as a reference; do not alias Tahoe firmware to this ABI |
| gxf-stack, `54799929` | Allocation-end stack-pointer fix already present by equivalent source content | No missing patch; ancestry alone would give a misleading answer |
| lina/gpu-wip, `11163540` | Changes concern exception/kboot code and GPU reserved-memory mapping; no newer AGX tracer/decoder changes relative to main | Review mapping ideas when hardware evidence calls for them |
| Existing AGX capture tools | Pause/resume, command dumps, queue/ASC/UAT tracing and filter hooks are already available | Adapt these when Tahoe guest execution and M3 address ranges are established |

The [upstream hypervisor documentation](https://asahilinux.org/docs/sw/m1n1-hypervisor/) lists 14.8.3 for M1–M3 and warns that firmware ABI versions matter. The firmware-version addition does not establish Tahoe GPU support: the inspected GPU version matrix still names G13/G14/G14X. We should reuse transport and capture structure while validating each decoder against actual M3/Tahoe evidence.

## Useful tooling already in our checkout

`proxyclient/hv/trace_agx.py` and `trace_agx_defer.py` demonstrate `AGXTracer`, command dump directories, and HVC 100/101 capture-window controls. `proxyclient/m1n1/trace/agx.py` supplies mapping, queue and firmware communication tracing. Some entry scripts contain hardcoded addresses; those are examples to adapt after checking the target, not portable configurations.

`GPUFrame.save` in `proxyclient/m1n1/agx/render.py` writes a ZIP containing command metadata, object metadata and binary object contents. This is a useful artifact pattern. **`GPUFrame.load` pushes objects to hardware**: it is not a host-only archive reader. The new catalog stores such attachments as opaque bytes and does not invoke it. Existing triangle and frame-render scripts likewise remain hardware experiments.

Upstream already automates tracing through Python. Our additional investment is reproducible experiment definitions, separate attempts, immutable raw artifacts, machine-readable comparisons, and eventually scheduling many offline analyses around serialized device execution.

## PR 622: correction and bounded candidates

[PR 622](https://github.com/AsahiLinux/m1n1/pull/622), checked at `ce1c1574757e19acc44fdd28fa49c7a500a23210`, is closed and describes partial M4/A18 Pro work, with M1–M3 untested. Its description says the tested SPTM emulator was tainted and unpublished. However, the inspected public tree **does contain `src/sptm/`**, whose README calls it “tainted bringup code” and describes optional `SPTM_EMUL=1` stage2 linkage. Earlier blanket statements that no public emulator code exists should therefore be replaced by this more precise finding.

This audit read that notice and the directory inventory, not the emulator implementation. Its provenance and compatibility remain unresolved; no emulator code was adopted, and the directory's existence does not demonstrate a usable M3/Tahoe boot path.

Separately inspected generic changes offer later candidates:

- [`de6e294c`](https://github.com/AsahiLinux/m1n1/commit/de6e294c6823f2693cd51783f9104fc642923c79): bounded XNU message-buffer dumping, useful once XNU starts and debug logging needs better capture.
- [`a51787aa`](https://github.com/AsahiLinux/m1n1/commit/a51787aad4884ae10ba8ca215e8de9e10025be5f): custom primary/secondary guest start entry and arguments. Potentially useful for full loader integration; our bounded probe already supplies an explicit entry and boot arguments.
- Timer shadowing and secondary-CPU state handling deserve focused comparison when those transitions are exercised. M4 guards and hardcoded kernel patches should not be applied as a bundle to M3.

No upstream native patch or pin changed during this audit. The work implemented now is the [experiment catalog and comparison foundation](experiment-automation.md). The critical hardware path remains monitor initialization, translated SPRR/GXF and exception transitions, then XNU startup and a bounded GPU capture.
