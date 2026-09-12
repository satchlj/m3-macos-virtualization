# Exact TXM context-entry one-step gate

[Directory index](README.md) · [Current project status](../STATUS.md)

> Research record: results and proposed steps below have the scope of this note;
> they are not a current setup guide.

Attempt 73 stopped at the rewritten SPTM ERET callback PC
`0xfffffe00070a410c` (the pinned original ERET is at `...4108`, word
`0xd69f03e0`). The guarded bank named runtime target `0xfffffe001703103c`
with SPSR `0x13c0`. Saved live tables resolve it to TXM `__TEXT_EXEC`, linked
`0xfffffff01703103c`, and the exact first 32 bytes hash to
`cef67431c02543f1848194725aa1a71be428f35c07ac64d7c7754c488faff4a8`.
The first instruction is `mov sp,x0`.

This is a TXM thread-stack entry/resume trampoline, not an ordinary return
site. Attempt 73 has `x0=0xfffffdf000188000`, `x16=0x2000000000001`, and
`x3=0`. The low 32 bits of x16 select stack initialization; TXM later checks
the 16 KiB alignment and whether the stack is already claimed. Continuing
past the first instruction would therefore authorize memory mutation and is
outside this experiment.

The opt-in `--xnu-txm-context-entry-one-step` gate requires the exact caller,
target, SPSR, registers, source ERET, live target bytes, and prior verified XNU
handoff. It independently walks the live target and x0 page using only owned
guest RAM. Both mappings must be AF and normal write-back with no hidden table
restriction. Live guest SPRR aliases must decode the target as guarded GL0 RX
and the complete aligned x0 page as guarded GL0 RW/NX.

On success the probe sets ELR/SPSR from the guarded bank, enables architectural
software-step, and resumes once. The very next callback stops unconditionally.
Only EC `0x32` at `0xfffffe0017031040`, with SP_EL0 and x0 both equal to the
original x0, proves exactly one retired instruction. Any gate or step mismatch
stops without a second resume. The general TXM return catalog is unchanged.

Every nonzero ERET target classification is retained in
`eret_classifications`, including rejected/error cases and the live roots. The
new gate evidence is retained in `xnu_txm_context_entry_one_step`.

Attempt 75 (`bac8fa9c-56b4-4008-9f9a-32d51750db5d`) hardware-validated the
one-instruction contract in 39.51 seconds. All gate checks passed and the exact
software-step arrived at `0xfffffe0017031040`, with SP_EL0 and x0 both equal to
`0xfffffdf000188000`. Guest return, cleanup, firmware fast-shadow disable, and
proxy health all passed.

The next 14 instructions from `...1040` are deterministic and do not access
memory. They reduce x0 to 1, take the aligned-stack branch, derive
`SP_EL0=0xfffffdf00018bc00`, and prepare x8 at
`0xfffffdf00018bc58`, x9=0, x10=1. The opt-in register-prefix probe checks every
software-step PC, PSTATE, and changed register, plus unchanged x16/x18. It stops
at `0xfffffe0017031084`, before executing `casb w9,w10,[x8]`, the first memory
and potentially mutating instruction. The exact continuation-source SHA-256 is
`14f527c547bfbb682ea82b6f633a77558640486ef69dd76e24f67dde9f0ab045`.

Attempt 76 (`ca705b9e-4384-4541-9f89-115cf95a8c71`) hardware-validated all
15 non-memory instructions in 39.37 seconds. It stopped at the CASB with the
exact predicted state and retranslated x8 to the same guarded writable owned
stack page. A read-only post-run VA read, without resuming the guest, confirmed
the first-touch byte was still `0x00`.

The next opt-in boundary executes only the pinned `casb w9,w10,[x8]` (word
`0x08a97d0a`). It requires the byte to be zero before launch, then stops at
`0xfffffe0017031088` and requires x9=0 plus a live post-step byte value of one.
This is a deliberate, bounded mutation of one byte in disposable guest-owned
RAM: the TXM stack ownership claim. No firmware or original machine RAM is in
scope.

Attempt 77 (`505eaf5d-b354-492f-8656-4d205354a607`) hardware-validated that
claim in 39.66 seconds. All 16 step records passed. The byte at VA
`0xfffffdf00018bc58`, PA `0x100179b7c58`, was zero before launch and one at
the exact `...1088` step; x9 was zero, proving the successful compare/store
rather than a preclaimed stack. Guest return and all cleanup checks passed.

The next instruction is `cbz w9`, which must branch to `...1098`. The following
bounded block writes only stack metadata within the same owned page before an
x18-dependent branch. Those writes require their own explicit source/state and
pre/post-byte contract; the claim flag must not be turned into general native
continuation.

## Post-claim metadata initialization boundary

The opt-in `--xnu-txm-context-stack-metadata-init` probe replays the complete
verified prefix and atomic claim, then permits exactly five more instructions.
With x9 verified as zero, `cbz w9` must branch from runtime `...1088` to
`...1098`; TXM then retires `str wzr,[sp,#4]`, `strb wzr,[sp,#0x79]`,
`mov x8,#1`, and `strb w8,[sp]`. The terminal software-step PC must be
`0xfffffe00170310a8`, before `cbnz x18` executes.

The gate pins the exact 36-byte source window through the unexecuted `cbnz`
(SHA-256 `8d15a9c9a1dd8080fb1276865c9fd73aaea4cb09b806dd6a73d9836c7b9fdf15`),
requires all four stack-header fields to start at zero, and preserves the
live GL0 RW/NX owned-page checks. It snapshots the full 16 KiB stack page
before entry and at the terminal step. The final page must equal the original
except for byte offsets `0x3c00` (initialized state) and `0x3c58` (atomic
claim), both changing from zero to one. The two zero stores are verified by
exact instruction retirement and final values; because their destinations
start at zero, they are not claimed as observed value transitions.

This boundary does not execute the x18 branch, complete TXM context entry,
establish a CALL_TXM return, allocate a frame, transfer frame-table ownership,
or mutate an XNU stage-1 descriptor.

Attempts 78–80 advanced this boundary one independently gated step at a time:

- Attempt 78 (`d3e38e77-490b-4766-9a71-f595a3df06a7`) verified all three
  metadata stores and stopped at `0xfffffe00170310a8` in 40.35 seconds.
- Attempt 79 (`4504287b-a1b6-4d52-9679-f015021989eb`) executed only the taken
  `cbnz x18`, rejected the SVC fallthrough, and stopped at `...10b8` in 39.97
  seconds before the outbound branch.
- Attempt 80 (`3fd50fa0-f2c2-433f-8377-f7e6acfefdd2`) executed only that
  outbound branch and stopped at the separately source-, live-byte-, mapping-,
  MAIR-, and guarded-permission-verified handler entry
  `0xfffffe001702edec` in 38.97 seconds, before `pacibsp`.

All three runs preserved the exact stack-page diff `[0x3c00, 0x3c58]`, returned
the guest cleanly, disabled the firmware fast path with verified readback, and
left the proxy alive. Attempt 80's archive SHA-256 is
`240ad01cff30a0b46f36a57490bc800b6f7c60bf233f90c14e8b4f77457de421`;
its event-journal SHA-256 is
`e46fdd7102e3daff211899616e61d62d0cb361ab5a5b930b885d947bb2344ce3`.

The next safe boundary is non-memory: execute the pinned `pacibsp` and
`sub sp,sp,#0x70`, carry the dynamically signed x30 across the second step,
and stop at `...02edf4` before the first `stp`. The later save block and handler
call remain out of scope.
