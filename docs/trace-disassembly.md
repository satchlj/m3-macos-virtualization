# Trace disassembly annotation

`scripts/trace_disassembly.py` lists the instructions around a recorded trace
event, a guest address, or the hottest PCs of a `trace_profile.py` output, and
annotates each with where it lives in the constructed guest image, the original
payload bytes, their disassembly, and the events recorded at that address. It is
host-side only: it verifies each payload's SHA-256 before reading, opens payload
files read-only, never opens a device and never executes guest code. Its output
is an observation of linked bytes and recorded events; it does not establish a
boot milestone, loop semantics, or full machine state.

```sh
python scripts/trace_disassembly.py RUN_BUNDLE --index 4123 --before 16 --after 8 --output listing.json
python scripts/trace_disassembly.py report.json.gz --index 4123          # retained window only
python scripts/trace_disassembly.py RUN_BUNDLE --pc 0xfffffe00070b0b20   # no trace correlation
python scripts/trace_disassembly.py RUN_BUNDLE --hot profile.json --before 2 --after 2
```

The listing is printed as text; `--output` also writes the full JSON by atomic
rename. `--payload-dir DIR` reads `NAME.macho` from another directory instead
of the paths recorded in the layout (the research payload lives under an
ignored `local/` path and may be absent); the recorded SHA-256 must still match.

## Address mapping

A run report's `layout` comes from `sptm_layout.plan`. `resolve(layout, va)`
maps a guest address to payload bytes in two steps and is a pure function:

1. Virtual addresses at or above `layout['virtual_base']` map to guest offset
   `va - virtual_base`. When `guest_base`/`guest_size` are supplied (the
   report's owned allocation), addresses inside it map to physical offset
   `va - guest_base`. There is no verified slide mapping for any other range.
2. The placement whose `[offset, offset+size)` covers the guest offset names the
   image and segment; `fileoff = segment.fileoff + (guest_offset - placement.offset)`
   when that lies inside `segment.filesize`.

Results are explicit: `mapped` (bytes exist in the payload file),
`outside-image-bytes` (a placed segment's zero-filled tail), or `unmapped`
(load-time regions such as `DeviceTree`, `TrustCache` and `BootArgs`, scratch
RAM beyond the constructed image, or addresses outside both windows). The
region name from `layout['regions']` is reported when one covers the offset.

## Original bytes versus what executed

The disassembly shows the linked payload bytes. Before loading, the probe
rewrites instructions in the sptm `__TEXT_EXEC` segment (`patch_probe_code` in
`sptm_entry_probe.py`, applied after upstream m1n1's `patch_synthetic_code`):
HCR_EL2, SCTLR_EL2 and SCTLR_EL1 accesses become `HVC #0x60xx`, registers in
the probe's EL2 list become `HVC #0x8xxx`, `ERET` becomes `HVC #0x6080`, and the
Apple words `0x0020142x`/`0x00201400` become `HVC #0x609x`/`HVC #0x60a0`. The
entry word is transiently replaced by `HVC #0x7ffe` and restored at the first
stop. The tool therefore never claims the shown bytes executed verbatim; each
row carries a `probe_rewrite` verdict:

- `rewritten`: an HVC trap (ESR EC 0x16) was recorded for this address while
  the original word is not an HVC. The detail names the observed immediates and
  categories and flags an immediate that differs from the one the original
  word predicts.
- `payload-hvc`: the payload itself contains the HVC that trapped.
- `candidate-not-observed` / `candidate-stepped-only`: `patch_probe_code`
  always rewrites this word, but the supplied events contain no HVC trap here
  (a software-step event only marks the instruction about to execute).
- `candidate-unresolved`: an MSR/MRS whose rewrite depends on the probe's
  register list (upstream m1n1 encodings are not modelled here).
- `original`: outside the patched segment, or no rewrite pattern and no HVC
  trap recorded; `patch_synthetic_code` rules are not modelled, so this is
  "no evidence of rewriting", not proof.
- `no-payload-bytes`: nothing to compare.

Events are correlated by the address of the instruction they describe. For HVC
traps the recorded `pc` is the architectural ELR, which is the instruction
after the HVC, so the tool uses `pc - 4`; step, trapped-MSR and abort events
use `pc` directly. The `center` object records this adjustment. Hot-mode
profile PCs are raw event addresses and are not adjusted, which the output
notes.

## Event sources and identity

A bundle directory supplies `manifest.json`, `report.json` and, when finalized,
`events.jsonl`. `--events auto` streams the archive when the manifest records a
matching `event_archive_identity` (SHA-256 and size are verified first and the
total count is checked against `trace_total_events`), otherwise it uses the
retained report window. `--events archive` refuses an unfinalized bundle, and
`--events window` uses only the retained window, whose indices must lie inside
`[trace_start_index, trace_start_index + len(trace))`. A bare report file only
ever offers its window. Manifest and report run IDs must agree, and a profile
given to `--hot` must carry the same run ID when it has one.

Archive streaming keeps memory bounded: per address in the window it keeps a
count, kind counts, HVC immediate counts and up to `--max-hits` sample events
(maximum 256), marking truncation. Windows are limited to 4096 instructions in
every mode, including the total across hot PCs.

## Disassembler

Homebrew LLVM 23's `llvm-objdump` rejects `-b binary`, so raw words are decoded
with `llvm-mc --disassemble --triple=aarch64 --mattr=+all -show-encoding`, one
instruction word per stdin line as little-endian hex bytes. Lines llvm-mc
reports as `invalid instruction encoding` (including Apple-specific words) are
kept as undecodable rows; every decoded line is matched back to its word by
line order and echoed encoding, and a batch that cannot be matched exactly is
retried one word at a time. Branch targets are printed as PC-relative literals.
The tool path can be overridden with `TRACE_DISASSEMBLY_LLVM_MC`; when no tool
is available the run fails with `DisassemblerUnavailable` rather than guessing,
and the unit tests that need it skip. The output records the tool, version and
invocation used.
