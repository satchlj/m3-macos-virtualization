# Phase 5.3 leaf-page binding

## Status

Attempt 111 established one selector-3 L2 table installation. Attempt 114
continued the same invocation to the exact selector-2 `sptm_map_page` call.
It stopped before the service because the original host gate misclassified the
leaf output frame as an unrelated FTE neighbor. No leaf PTE mutation is claimed
before a hardware run passes every corrected gate below.

## Exact path and ancestry

The selector-3 return at runtime `0xfffffe002b7ef120` is inside `pmap_expand`,
while the leaf call at `0xfffffe002b7efa60` is in a separate helper. A direct
PC seek is therefore insufficient. The trace binds the two through saved stack
ancestry:

- at the selector-3 return, `pmap_expand` saved parent `x27` at `SP+0x118`,
  saved parent `x19` at `SP+0x158`, and saved LR at `SP+0x168`; its parent SP is
  `SP+0x170`;
- saved LR must identify source/live-verified call `0xfffffe002b7ee37c`
  returning to `...ee380`, or call `...ee6b4` returning to `...ee6b8`;
- `[saved x19+8]` must contain the same root used for selector 3;
- at the leaf call, helper `SP+0x90` must equal the captured parent SP, saved LR
  at `SP+0x88` must identify source/live-verified call `...ee0b4` returning to
  `...ee0b8`, or call `...ee130` returning to `...ee134`;
- leaf `x1` must equal the saved parent `x27` and must select the same L1/L2
  indices as the installed table.

Unrelated hits at the same leaf-call PC are rearmed only when their parent SP
is different. A matching parent frame with any failed invariant stops closed.

## Selector-2 proof

The straight-line leaf preparation and service path are pinned as follows:

- `0xfffffe002b7efa50`: `ldr x0, [x20, #8]`, word `0xf9400680`;
- `...efa54`: `mov x1, x24`, word `0xaa1803e1`;
- `...efa58`: `mov x2, x21`, word `0xaa1503e2`;
- `...efa5c`: `mov w3, #0`, word `0x52800003`;
- `...efa60`: leaf wrapper call, word `0x941e2a9e`;
- wrapper entry `0xfffffe002bf7a4d8`, word `0xd503237f`;
- selector 2 at `...a4e8`, word `0xd2800050`;
- `genter` at `...a4ec`, word `0x00201420`;
- post-service helper at `...a4f0`, word `0x97db1f60`;
- wrapper `RETAB` at `...a4fc`, word `0xd65f0fff`;
- caller return `0xfffffe002b7efa64`, word `0x7100081f`;
- SPTM `gexit` `0xfffffe00070a4520`, word `0x00201400`.

The trace independently recomputes the L2 slot from root and leaf VA, requires
the selector-3 descriptor to remain exact, and computes the L3 slot as:

```
table PA + (((leaf VA >> 14) & 0x7ff) * 8)
```

Before selector 2, the entire owned 16 KiB table must be zero. The output
descriptor must be valid, have a nonzero 42-bit page-aligned output PA wholly
inside owned guest RAM, and use flags zero. After a status-zero authenticated
round trip, the entire table must equal its preimage except for the target
eight bytes, which must equal `x2`. The L2 descriptor must remain exact. The
table FTE must remain unlocked with its branch-specific type and stable generic
fields. Attempt 114 showed that the table frame's `+16` FTE is exactly the
independently derived FTE for the adjacent leaf output page. The corrected gate
requires this record to change from unlocked type `0x0b` to unlocked type
`0x19`, with byte 2 as the only changed byte. The table record and unrelated
`-16` neighbor must remain byte-for-byte exact. The selector-2 caller's
source-type stack argument and its source/live-verified load at
`0xfffffe002b7ee12c` are recorded without equating that argument to the
resulting FTE type.

Each seek leg is limited to `1<<24` forwarded steps, total leaf tracing to
`1<<26`, and rearming to 16. A passing run stops with
`phase53-leaf-page-bind-reached`. This would establish one live leaf insertion,
not arbitrary runtime page-table coverage or a macOS boot.

## Hardware approach — attempt 114

Run `195e73b0-28f3-4d1f-afb7-99f01c657114` reached the target after five prior
survey calls and completed the selector-3 descriptor bind. At the leaf call it
proved root `0x10015060000`, VA `0xfffffe2057ff8000`, descriptor
`0x4600100187fc683`, flags zero, table PA `0x100187f8000`, L3 index 2046, and
empty slot PA `0x100187fbff0`. The full 16 KiB table was zero and the L2
descriptor remained exact.

The only failed check was the old `fte_neighbors_unchanged` rule. The table
FTE center at `0xfffffdf000029fe0` remained exact, as did its `-16` neighbor.
The `+16` record changed only its type byte from `0x0b` to `0x19`; this record
is exactly the FTE computed independently from output PA `0x100187fc000`.
Thus the run is evidence for pre-service output-frame preparation, not a leaf
mapping. Guest execution took 44.90 seconds, returned cleanly, and left the
proxy alive. Archive SHA-256:
`1acc6572623c6fedd915e48259ed5864afe0376724dbcaf886a6d6390cbd832c`.
Event archive SHA-256:
`525d9b69ca9c858ea564904ab6b49df4d0b5a0a354c52ed8cd3c98710d1a6bdf`.

## Corrected-gate replay — attempt 115

Run `59ffcdb6-f468-453b-bc5f-f4360bcbc8c2` reproduced the same target in
44.80 seconds. It independently confirmed output PA `0x100187fc000`, exact
positive-neighbor FTE aliasing, source-type stack argument `0x19`, and the
byte-2-only unlocked `0x0b` to `0x19` transition. Every new output-participant,
source/live code, ancestry, table, descriptor, and ownership check passed.

The sole rejection was a narrower host baseline error:
`fte_unrelated_records_unchanged` compared the table center against its image
before selector 3. Selector 3 had already made the accepted opaque byte-6
change from zero to one. The leaf gate now uses the verified selector-3
caller-return FTE image as its baseline, while retaining the earlier image to
prove the output record's `0x0b` origin. No selector-2 service was entered in
attempt 115, so it still does not establish a leaf mutation. Archive SHA-256:
`33ded5f3930c75a70b6bde1ee46e0a9d68e5ca132aa95098585c601780b969e5`.
Event archive SHA-256:
`d0f136c5ed760d9fc7cc9e03dd2cbdaa7e279de6667e8b3b64e6a5edcabec475`.

## First complete selector-2 round trip — attempt 117

Attempt 116 was a clean no-candidate boot, bounded in 48.17 seconds by the
short survey step limit. Attempt 117 then used the opt-in pinned Attempt-108
entropy replay. The report proves that only `/chosen/random-seed`,
`/chosen/cl4-entropy`, and `/chosen/boot-nonce` were replaced and that each
rebuilt value matched its pinned source hash.

Run `cff00e68-e314-4cba-8454-1b43ffbe09ff` found the target and completed the
entire selector-2 service and authenticated return path. Service status was
zero, the L2 descriptor remained exact, and the 16 KiB L3 table changed only
at the independently computed eight-byte slot, which became the exact leaf
descriptor. The final gate stopped only because it still required both table
neighbors to remain byte-for-byte exact.

The final FTE diff is narrower and structured: the unrelated `-16` record was
exact; the table center and exact output record each remained unlocked with
types `0x16` and `0x19`, respectively, while only byte 8 changed from zero to
one in each. The corrected final gate requires precisely those two byte-8
transitions and keeps the unrelated record exact. Attempt 117 therefore
establishes execution of the leaf service and the exact table mutation, but is
retained as a gate-rejected approach until the corrected final rule replays.
Guest execution took 45.78 seconds and returned cleanly with a live proxy.
Archive SHA-256:
`08748e3d6b31b5527d0d114f5fe0cd65899c64478f716e3ce992739c191e94a5`.
Event archive SHA-256:
`a346732ffa8216b2b298c217a3f2a823a2909a56b81add6b9a7cbad1a1fbed24`.

## Hardware validation — attempt 119

Run `def50c86-5500-41b0-8d3d-517fa3f142c7` passed every corrected gate and
stopped at `phase53-leaf-page-bind-reached` after 44.50 seconds. From root
`0x10015060000` and leaf VA `0xfffffe17ec00c000`, the trace bound the same
`pmap_enter` invocation to newly installed L3 table PA `0x100187f0000` and
independently computed empty slot PA `0x100187f0018`. Selector 2 returned
status zero through the source/live-verified authenticated path. The table's
only mutation was that slot becoming exact descriptor `0x4600100187f4683`,
mapping owned output PA `0x100187f4000`; L2 descriptor `0x100187f0003`
remained exact.

The pre-service output FTE retyped from unlocked `0x0b` to unlocked `0x19`
with only byte 2 changing. Across the service, the unrelated FTE remained
exact and the table/output FTEs remained unlocked types `0x16`/`0x19`, with
only byte 8 incrementing from zero to one in each. Static SPTM disassembly
locates the corresponding output- and table-frame reference-count increments
inside the selector-2 map path. The final tracer now also rechecks FTE base,
center, pointer translation, record completeness, and access properties;
Attempt 119's archived values satisfy those added structural predicates.

Guest return, timer restoration, fast-path teardown, and proxy health all
passed. This completes the bounded Phase 5.3 objective: one kernel-driven
allocation/ownership-transfer chain tied to a live Stage-1 table installation
and leaf mutation. It does not prove general SPTM compatibility or a full
macOS boot. Report SHA-256:
`564999b888369d73fc2356163329dc35fce49b7c9ff4fa8f17d828e119f32296`.
Archive SHA-256:
`20aa5cc6dc8d0c913096d2f7ca3c3cfea40bd48522b6b8ad905383a3496ae4b8`.
Event archive SHA-256:
`0f1d216e899c06ad5ca3ed0d1390023f4203f028c1dccdca2cfa700af8550320`.

The three-property entropy replay is useful for controlled repetition but is
not a deterministic candidate selector: attempts 118 and 120 applied the same
pinned values yet ended at the bounded survey step limit, while 117 and 119
found the target. Copying the remaining varying physical-address properties
would create invalid or unowned mappings and is not justified.
