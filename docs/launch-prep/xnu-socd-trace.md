# Private SOC diagnostic trace buffer

Attempt 66 (`1755ffa6-2b38-4d70-9db0-7716b2838a26`) stopped at runtime
`0xfffffe002b72118c`, linked `0xfffffe000b72118c`, instruction `0xb9000169`
(`str w9, [x11]`). The captured value is 2, with syndrome `0x93890046` and
FAR `0xfffffe003a61d014`: a 32-bit write blocked by stage-2 translation.

Archived final guest tables translate the address to `0x2ede69014`. The
archived host device tree identifies exactly that address as `/socd-trace-ram`
reg[0], size `0x39c` (924 bytes). The instruction begins a sequential diagnostic
trace structure initialization, with nearby exported SOCd client symbols.
This buffer is RAM, not a peripheral register bank.

The private backing design preserves the guest's original address and copies
only the 924 bytes named by the device tree. They occupy offset `0x1014` in a
separate zeroed 16 KiB private page. No surrounding original bytes are read,
and no original buffer write is performed. The remainder of the private page
is zero padding exposed by the required 16 KiB mapping granularity. The private
allocation must be outside the guest identity-mapped allocation and other
private backing allocations.

The exact source instruction, runtime PC, syndrome, value, FAR, translated IPA,
and live DT tuple must match before the first map. The map uses ordinary RAM
stage-2 attributes, consumes one page of the on-demand budget, and is followed
by the established translation invalidation sequence before retrying the
same instruction. Later guest writes are confined to private backing. This
continuation passed production callback replay and the full activated suite
(398 tests, one skipped). Other private allocations are disjoint because they
are successive owned allocations from the same allocator; the explicit span
checks additionally reject overlap with guest identity and original SOCd RAM.

The source fault and table evidence are in the attempt-66 archive, SHA-256
`e75668112c200668bcb084de502bb27c4d7af90a119caade3c5aae95f89436bc`.


Attempt 67 (`b663ee5f-85db-4557-b383-a13c7b0de731`) failed during host setup:
`node.device_type` normalized the actual `device_type` key to `device-type`.
The fix reads the exact raw property. A real archived-ADT integration now
executes the production lookup and validates its tuple/padding. The failed
attempt performed identity/register/ADT reads only, before any allocation,
copy, mapping, VEL2 activation, or guest execution. Attempt 67b therefore uses
the same fresh boot and a new output directory. Pipeline failures now include
a bounded original console traceback in their compact result.


The pinned direct call chain places `_socd_client_reinit` under
`AppleARMWatchdogTimer::callPlatformFunction`: reinit calls the common
initializer at linked `0xfffffe000b720ffc`, which contains the captured fault. The caller at linked
`0xfffffe0008aa0ce4` then checks kernel/SOC watchdog enablement and conditionally
calls `AppleARMWatchdogTimer::enableAPWatchdog`. A later read-modify-write in
that routine may require a watchdog register mapping, but its exact address
and execution are not established by this prediction. It is not part of the
private SOCd RAM mapping.


## Hardware validation — attempt 67b

Run `3705e54c-d809-4e19-988a-af440f0df484` copied exactly 924 source bytes,
read no adjacent original bytes, and verified the entire private page.
The original tuple was all zero at copy time, with source SHA-256
`ce7c16adff608d624a412164fdc692305fb461f4b14f9167e6efa78dbbad12ba`.
Private-page SHA-256 was
`4fe7b59af6de3b665b67788cc2f99892ab827efae3a467342b3bb4e3bc8e5bfe`.
The mapping succeeded at the exact expected write and XNU continued to a new
native exception at `0xfffffe002b641e00`, syndrome `0x07e00001`.

The run captured 14338 events in 145.25 seconds. Guest return and proxy health
were verified, as were all three timer/redirection restoration paths. The
new trap is under classification; full macOS boot is not established.
Event-journal SHA-256:
`bea7756a4cbd811a3c5474175cbe76e89f05bc31710ed290405354d8321d244e`.
Current RAM is retained for the next diagnosis.

Transfer-archive SHA-256:
`48234df98817c674ac9d1895e8ab3f6a3d20cbfe28c90540b2cb3ef9e8459ec8`.
