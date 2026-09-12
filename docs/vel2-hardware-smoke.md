# Virtual EL2 hardware smoke — 2026-09-09

The first MMU-off synthetic virtual EL2 test passed on the M3 Air (Mac15,12 / J613 / T8122). This is real hardware execution of our synthetic program, not monitor or macOS guest boot.

## Procedure and observations

The dedicated test installation booted into the installed baseline proxy. We verified `.init`, `.text`, and `.rodata` against its relocated raw ELF. We then RAM-chainloaded the experimental `m1n1.bin` using the baseline `chainload.py -r`, preserving SEPFW. The proxy returned successfully. The smoke runner compared the same sections against the experimental raw ELF before allocating or entering its guest.

The runner maps only three allocated 16 KiB pages through stage 2, disables guest stage-1 translation, and executes synthetic code on the boot CPU. Other CPUs are initialized by upstream `hv_init` but are not launched into this guest. No target disk write or boot-policy change occurs.

Observed register assertions all passed:

- CurrentEL reads 8 in virtual EL2 and 4 after ERET into virtual EL1.
- TPIDR_EL2 preserves the written value `0x1234`.
- HVC `0x12` from virtual EL1 enters the virtual EL2 lower-EL synchronous vector.
- ESR_EL2 is `0x5a000012`; ELR_EL2 points after that HVC; SPSR_EL2 is `0x3c5`.
- Virtual EL2 and EL1 stack pointers match their distinct assigned values.
- ERET from the handler returns to virtual EL1, reaching the completion marker.
- HVC `0x7fff` stops as intended; `EXIT_GUEST` returns to the proxy and a subsequent proxy NOP succeeds.

The runner initially encountered two host preflight errors (an incorrect HV_EVENT import and ELF relocation-section padding). Both were corrected before any guest execution. The first actual guest execution passed. The script was subsequently hardened to record unexpected event types and exceptions; the recorded successful run predates those reporting-only changes.

## Reproduce

Start with a freshly booted baseline and the exact pinned experimental build. Source `setup/activate.sh` with the correct ASAHI_ROOT. Select the actual proxy serial device explicitly. RAM chainload first:

```sh
export M1N1DEVICE=${M1N1DEVICE}
python "$M1N1_CHECKOUT/proxyclient/tools/chainload.py" -r "$VEL2_CHECKOUT/build/m1n1.bin"
python scripts/vel2_smoke.py --execute --device "$M1N1DEVICE" --report "$ASAHI_ROOT/vel2-smoke-hardware.json"
```

For compilation only, omit `--execute` and `--device`. The runner never opens a serial device in this mode. A mismatched running image is rejected before guest setup. An unexpected guest exception requests guest exit rather than continuing execution. If USB or the host hypervisor fails, save the output and manually return through startup options; do not retry blindly.

## Limits and next test

This establishes the first register and exception-transition path only. It does not establish MMU virtualization, GXF, asynchronous exception handling, monitor loading, or SPTM/TXM execution. Next validate unsupported-operation stops on hardware (in particular SCTLR translation-enable requests), then develop the translation contract with tests. The experimental proxy remains running in RAM after this test; rebooting the dedicated test installation restores the installed baseline.
