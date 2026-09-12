# Launch harness — what already exists (2026-09-10)

Investigating the loader/layout revealed the boot harness is **largely already built**.
This narrows the launch prep dramatically.

## The full collection is already loaded every run

`scripts/sptm_layout.py` loads and places all three images: `sptm`, `txm`, and
`kernelcache` (the full kernel collection). It places, into ADT-consistent ranges:
- SPTM + TXM monitor segments,
- `BootKC-rx` (__TEXT_EXEC), `BootKC-bx` (__TEXT_BOOT_EXEC = XNU boot entry),
  `BootKC-ro` (__TEXT/__PRELINK_TEXT/__DATA_CONST), `BootKC-rs` (__DATA_SPTM),
  `BootKC-rw` (__PRELINK_INFO/__DATA), `BootKC-le` (__LINKEDIT).
- `virtual_base = kernelcache vmin & ~((1<<36)-1)`.

The probe (`sptm_entry_probe.py`) then builds the ADT (`adt.build()`), rev-3 bootargs
(virt/phys base, mem size, top_of_kernel_data, devtree ptr/size, video, cmdline), and
places a **real trustcache read from target M3** (`iface.readmem(tc_addr, tc_size)`).
Guest RAM is ~226 MB and holds the whole thing.

So XNU is in the guest at entry **`0xfffffe000bfb0000`** (kernelcache LC_UNIXTHREAD pc
= __TEXT_BOOT_EXEC). SPTM has a real XNU to launch.

## Why SPTM idles instead of launching

SPTM boots (guarded per-CPU init, MMU, SPRR) and parks at the normal-world idle
(`0xf8b88`, EL1) in **STATE_XNU** — waiting. From the state-machine decode,
**ENTER_GUEST (x16=0x1b) is the valid idle transition** (event 12 -> action `0xa424c`
-> `0xa416c` full guest restore + eret to XNU). So the launch trigger is a single
guarded call we can already issue with the multi-call driver.

Open (the launch-requirements subagent is confirming): did SPTM populate the XNU
launch context (ctx+496 / per-CPU frame -> entry `0xbfb0000`, bootargs ptr) during its
boot from the loaded collection + bootargs? If yes, ENTER_GUEST launches XNU directly.

## Revised launch plan (much narrower)

1. Confirm SPTM prepared the XNU launch context during boot (subagent).
2. First launch attempt = multi-call driver with **x16 = 0x1b (ENTER_GUEST)** from
   idle, single-stepped, bounded. Observe the eret to XNU (`0xbfb0000`) and how far
   XNU gets before it needs something (a SPTM call, MMU, a device) our HV must handle.
3. The hard part is now the **running XNU** (the "full guest boot" tail): each thing
   XNU does — guarded calls, stage-2 faults for real devices, MMU — the HV/probe must
   service. That is the large, incremental work; the launch trigger itself is cheap.

## Risk

ENTER_GUEST starts a real OS: high commitment, mutating. First attempt must be
single-stepped and bounded (observe the entry, don't let XNU run free), with the
fresh-boot-gate + one-run-per-boot discipline and the reversibility plan.
