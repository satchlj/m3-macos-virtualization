# XNU/SPTM map-progress classifier

`classify_xnu_map_progress.py` streams a finalized run's verified event journal
and reports selector-2 `MAP_PAGE` activity without using JavaScript or `jq` for
64-bit guest addresses.

```sh
source setup/activate.sh
python scripts/classify_xnu_map_progress.py \
  artifacts/runs/observe-sprr/attempt-70/runs/RUN_ID \
  --output /tmp/attempt-70-map-progress.json
```

The classifier requires a finished manifest and complete event capture. It
checks the journal SHA-256 and size recorded by the manifest, validates every
event index, and checks the report's total event count. It then reports:

- the final verified event and cleanup/watchdog state;
- total and unique `(root, VA, PTE PA, flags)` map tuples;
- exact tuple repetition counts;
- fixed-delta map segments, the terminal `+0x4000` VA/PTE segment, and a
  separate terminal `+0x4000` VA segment that tolerates allocator-selected
  physical-page discontinuities; and
- the number of journal events after the last map.

The selector contract is the pinned SPTM service entry at
`0xfffffe00070a452c`, with selector 2 in `x16`, root in `x0`, VA in `x1`, and
the raw PTE in `x2`. A different payload must revalidate that contract before
using this tool.

## Interpretation boundary

The tool deliberately emits `loop_classification: not-demonstrated`. A watchdog
stop, hot PC, or repeated address is not a loop proof. A loop claim still needs
a repeated full control-state cycle with no intervening advancement and a
source/disassembly identification of the enclosing loop. Fixed-delta segments
are progress evidence only for the tuples they contain; they do not establish a
remaining page count or a macOS boot milestone.

The classifier reproduced the non-loop boundary for attempts 69 through 71
and classified attempts 72 and 73 as 894/872 and 896/873 total/unique tuples.
Their terminal stops were real native/ERET frontiers after the last map rather
than watchdog claims. These counts are comparable progress markers, not an
instruction-level performance benchmark.
