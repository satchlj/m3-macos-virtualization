# Phase 5.3 page-table descriptor binding

## Status

Attempt 111 verified the first live Stage-1 table installation associated with
a kernel-driven `XNU_PAGE_TABLE` transition. The run returned cleanly with a
live proxy. The next frontier is the first leaf PTE inserted into that table.

## Pinned path

The target retype is in `pmap_expand` at runtime `0xfffffe002b7eefe4`.
For Attempt 111 physical frame `0x10018004000`, the following path constructed
table descriptor `0x10018004003` and called `sptm_map_table`:

- caller return after retype: `0xfffffe002b7eefe8`;
- destination TTE KVA saved at active caller `[sp + 0x58]`;
- 16 KiB-aligned mapping VA saved at `[sp + 0x48]`;
- map call: runtime `0xfffffe002b7ef11c`, linked
  `0xfffffe000b7ef11c`, word `0x941e2cf9`;
- selector-3 wrapper entry: `0xfffffe002bf7a500`, word `0xd503237f`;
- selector setup: `0xfffffe002bf7a510`, word `0xd2800070`;
- `genter`: `0xfffffe002bf7a514`, word `0x00201420`;
- post-service helper: `0xfffffe002bf7a518`, word `0x97db1f56`;
- wrapper `RETAB`: `0xfffffe002bf7a524`, word `0xd65f0fff`;
- caller return: `0xfffffe002b7ef120`, word `0xf94053e9`.

At the map call the arguments were `x0` equal to the saved kernel
TTBR1 root (`0x10015060000`), `x1` the 16 KiB-aligned VA
selecting the destination L2 entry, `w2=2`,
and `x3=0x100187f4003`. The binary path is the execution authority; public XNU
source supplies only the semantic label and the documented
`sptm_map_table(pmap->ttep, v, ttlevel, new_tte)` relationship.

## Hardware result

The opt-in trace captured the TTE KVA before selector 3, translated it
through the saved guest tables, and read its old value. It must independently
walk from `x0` and `x1` using the verified 16 KiB geometry:

```
L1 descriptor = root + (((x1 >> 36) & 0x7ff) * 8)
L2 slot PA     = table(L1 descriptor) + (((x1 >> 25) & 0x7ff) * 8)
```

The calculated L2 slot PA `0x10017a2c838` equaled the physical translation of
the saved TTE KVA. Its old value was zero. After the exact selector-3
`genter`/`gexit` round trip and authenticated return, the same slot contained
exactly `0x10018004003`. The service returned status zero. The authoritative
FTE remained unlocked and type `0x14`; both adjacent FTEs were unchanged.
Opaque byte offset 6 changed from zero to one. Existing FTE evidence permits no
universal interpretation of bytes 3--15, so the corrected gate records this
delta while requiring the generic lock/type fields and neighbors to remain
stable.

Every terminal requires the pinned source word, identical live word, level-3
translation, access flag, exact software-step status, same-PC rearm echo, and
bounded filter contract. The added path is limited to `1<<22` aggregate
forwarded steps and 16 rearms, with `1<<20` per leg. Any alternate race branch,
root mismatch, slot disagreement, unexpected descriptor, service error, or
budget exhaustion stops without asserting a mutation.

All other 43 final checks passed in run
`d50e65a3-5c5e-46f2-a4ec-6febe6838185`. Guest execution took 43.32 seconds;
the report SHA-256 is
`3dc2249e1dae5c152a74b105b849ddf618b49c7b20e08e09e5b59b476d9c419b`
and archive SHA-256 is
`71193765350ca46b437e652a92bde60a1bd81bc9a1a3e21090f6b25b883e2c0e`.
The legacy stop reason records the now-corrected full-record-equality host
false-negative; it does not denote a target failure. This establishes one live
dynamic Stage-1 table installation, not general allocator coverage, arbitrary
runtime page-table mutation, or a macOS boot.

The machine-readable correction can be reproduced without target access:

```
python scripts/revalidate_phase53_descriptor_bind.py \
  --report artifacts/runs/observe-sprr/attempt-111/report.json
```

It binds its result to the source report SHA-256, permits only the legacy
`fte_center_unchanged` false check, independently rechecks the descriptor and
slot identities, and rejects any generic-field or neighboring-record change.
