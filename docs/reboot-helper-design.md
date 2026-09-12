# Guarded target reboot

The helper in `scripts/clean_reboot_target.py` follows the ordering used by
upstream m1n1's reboot tool:

1. connect to a live m1n1 proxy;
2. call `PMU(u).reset_panic_counter()`;
3. request the proxy watchdog reset;
4. wait for USB re-enumeration and require a fresh proxy NOP.

The PMU step is essential. A direct `p.reboot()` previously incremented the
abnormal-reset breadcrumb until iBoot demoted the selected boot object. The target
then booted recovery/macOS instead of returning to m1n1.

The helper is dry-run by default and requires both an explicit serial device and
`--execute`:

```sh
python scripts/clean_reboot_target.py --device "$M1N1DEVICE" --execute
```

This does not make reset unattended or universally safe. m1n1 must already be the
selected default boot object, the owner must authorize the reboot, and local
recovery access must be available. If the proxy does not return, do not repeat the
reset blindly; inspect the target's startup selection locally.
