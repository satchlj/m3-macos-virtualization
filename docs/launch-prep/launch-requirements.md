> **Superseded by hardware, 2026-09-11:** The slot `0x98928` and the erets described below target TXM, not XNU. The candidate XNU entry is in `0x98930`. Full SPTM boot and XNU launch are unproved. Treat the interpretations below as historical; see [the correction](world-switch-is-the-launch.md).

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

# SPTM XNU-launch requirements (decoded 2026-09-10)

SPTM build `SPTM-611.161.4|2026-07-31` (t8122 / Tahoe 25G83). SPTM runs at EL2+VHE
inside GXF; XNU is the non-guarded EL1 host.

## ENTER_GUEST launch handler (0xfffffe00070a416c)

Per-CPU base = `mrs S3_6_C15_C11_1`; launch ctx = `percpu + 2608`; guest GPR/SIMD save
area at `ctx+496`. The handler restores x0-x30 (`ctx+496 + 8*N`) and q0-q31
(`ctx+496 + 288 + 16*N`), then programs the GXF return state and erets:
- guest ELR `S3_6_C15_C10_6` <- **[global 0xfffffe0007098928]** = the XNU entry PC.
- guest SPSR `S3_6_C15_C10_3` <- `0x13C0` (EL1, DAIF masked).
- `eret` at `0xa4248` -> XNU.
It does NOT set TTBR/SCTLR/TCR/MAIR/VBAR/ELR_EL1 — those were prepared earlier.
Full ctx+496 record: x0..x30 @+0..+240, SP_EL0 @+248, q0..q31 @+288..+783,
FPSR @+800, FPCR @+804. **x0 slot (ctx+496) = the XNU boot_args pointer.**

## SPTM prepares the XNU context during its OWN boot (not at ENTER_GUEST)

- Entry PC -> global `0x98928`, written at `0xbef84` in `sptm_bootstrap_early`
  (~0xbdc00-0xbf100), from the Boot-Kernel-Collection region base + slide.
- XNU EL1 translation (TTBR0/1, MAIR, TCR, SCTLR, CPACR) -> a saved-context block,
  applied via `_EL12` aliases in the domain switch at `0xe8ff8`.
- SPTM finds all of it by parsing the **device tree** `chosen/memory-map`, using
  named regions: `BootKC-entry/virt/bx/rx/ro/rs/rw/le` (kernelcache), `TXM-*`,
  `SPTM-*`, `CL4-*`, `TrustCache`, `ExclaveOSTrustCache`, `slide`/`PHYS_SLIDE`,
  `xnu_ro_pagetables_begin/end`, `kernel-ctrr-to-be-enabled`, `has-virtualization`,
  cpu impl-reg regions, and the `/chosen/memory-map/BootArgs` property (XNU boot_args
  ptr -> guest x0). SPTM bootstrap args (x0 at entry `0xac388`->`0xaf000`): rev>=3,
  virt_base(+8)/phys_base(+16)/size-flags(+24), handoff ptr(+1152) stamped "SPTM"+v3.
  (Note: x0 = SPTM bootargs; the public start_sptm.s x0/x1/x2 convention does NOT
  match this build.)

## Consequence: our harness is (very likely) launch-ready

The probe already: loads the full collection (BootKC/TXM/SPTM segments), uses
target M3's REAL ADT (which has the correct `chosen/memory-map` region names) and
overwrites those region entries with the guest's loaded addresses, builds rev-3
bootargs, and places a real trustcache. attempt-24's boot-data audit confirms the
memory-map names BootKC/TrustCache/SPTM/TXM at guest addresses. SPTM boots to idle
cleanly (no bootstrap panic). So SPTM most likely PREPARED the XNU context (entry-PC
global 0x98928 populated, translation block filled) during its boot.

**Therefore the launch trigger is a single ENTER_GUEST (x16=0x1b) from idle** — which
the multi-call driver can issue. The first attempt is both the test and the milestone:
single-step the eret and confirm it lands at the XNU entry (`0xfffffe000bfb0000`,
kernelcache LC_UNIXTHREAD pc), not garbage.

## First-launch run design (attempt-25, to build)

- Add a diagnostic: snapshot the entry-PC global `0x98928` at boot/exit to confirm
  the context is prepared before the eret.
- Issue ENTER_GUEST (x16=0x1b), single-step the eret into XNU, RECORD the landing PC,
  and STOP after a bounded number of XNU instructions (do not let XNU run free).
- Confirm landing == `0xbfb0000`. Then the incremental "running XNU" work begins:
  each guarded call / stage-2 fault / MMU op XNU makes, serviced one at a time.

## Risk / commitment

ENTER_GUEST starts a real OS: the highest-commitment, mutating step of the project.
First attempt must be bounded + single-stepped, fresh-boot-gate + one-run-per-boot,
with the reversibility plan. Get explicit go before running.
