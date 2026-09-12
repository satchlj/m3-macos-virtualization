# Correction: the first world-switch eret enters TXM (2026-09-11)

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Hardware attempts 40 and 41 supersede the previous conclusion in this file.
**SPTM reaches and enters TXM.** At that checkpoint, XNU execution and full SPTM
initialization were not established. Attempts 48–49 later proved the distinct
native `gexit` launch; this particular `eret` still targets TXM. See the
[post-TXM path](post-txm-svc-path.md).

## What was correct

`patch_synthetic_code()` rewrites `eret` to `HVC #0x4800` (`ERET_HVC`). The
instruction at runtime VA `0xfffffe00070a4e44` is an eret, not an original HVC.
Its target comes from `ELR_GL1`, with `SPSR_GL1 = 0x13c0`. The aliases used by
`HV.MSR_REDIRECTS` work inside the callback on hardware.

## What hardware disproved

Attempt 40 read `ELR_GL1 = 0xfffffe0017070000`, not `0xfffffe000bfb0000`.
The old handler continued to this nonzero target, then the new watchdog recovered
a guarded vector loop after 120.39 seconds. Proxy NOP and cleanup succeeded.

Post-exit bounded read-only inspection translated the target to PA `0x1000fee8000`,
inside the loaded **TXM-bx / __TEXT_BOOT_EXEC**, file offset `0x6c000`. All 64 bytes
read there exactly matched the TXM payload. The linked TXM entry is
`0xfffffff017070000`. Attempt 41 independently verified the entry and 32 payload
bytes before transfer, then captured 256 single-step events in TXM.

The globals are:

| SPTM runtime global | Actual contents after attempt 40 | Identity |
| --- | --- | --- |
| `0xfffffe0007098928` | `0xfffffe0017070000` | TXM entry, translated and byte verified |
| `0xfffffe0007098930` | `0xfffffe002bfb0000` | Candidate BootKC/XNU runtime entry; not execution evidence |

Disassembly confirms the producer at `0x70bf060..0x70bf0b0` consumes
`TXM-entry`, `TXM-ro`, `TXM-virt` and stores at `0x7098928`. The following block
consumes `BootKC-entry`, `BootKC-ro`, `BootKC-virt` and stores at `0x7098930`.
The former docs mislabeled the first slot as XNU.

The epilogues at `0x70a416c` and `0x70a4d74` both consume the TXM slot; they are
**not byte-identical**, contrary to the previous handoff. The latter initializes
additional state rather than restoring the former's complete register frame.

## Current probe contract

The free-run eret handler resolves the actual target through live guest page
tables into owned loaded RAM, matches it to the image's linked entry and original
payload bytes, and requires the observed `0x13c0` return state before continuing.
No hardcoded XNU VA-range heuristic remains. Default behavior stops before
transfer (`handoff-txm-entry` or `handoff-xnu-entry`); that stop alone does not mean
an instruction executed. `--handoff-steps 1..4096` permits a bounded single-step
window after the verified transfer and stops on the first non-step event.

## Evidence (private local artifacts)

- `artifacts/runs/observe-sprr/attempt-40/report.json`
- `artifacts/attempt40-target-classification.json`
- `artifacts/attempt40-launch-disassembly.txt`
- `artifacts/runs/observe-sprr/attempt-41/report.json`
- Detailed continuation: [post-TXM service path](post-txm-svc-path.md)
