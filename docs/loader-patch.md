# Local loader patch

Baseline: public AsahiLinux/m1n1 commit `940439b9a407fbfc499bea933269219f3f62d4c7`. The patch is authored locally from public Python source; no proprietary binary analysis, firmware alias, GPU ABI guess, or target execution is involved. `upstream.lock` records baseline file hashes, patched file hashes, and the exported patch hash. The local removal of AGENTS.md is not part of this patch.

Apply to a clean checkout at that commit:

```sh
git apply --check /path/to/research/patches/m1n1/0001-validate-guest-setup-and-report-stages.patch
git apply /path/to/research/patches/m1n1/0001-validate-guest-setup-and-report-stages.patch
```

Unsupported bootargs revisions now raise before HV.init device operations and before load_raw allocation/upload. The actual Construct serializer validates existing fields, accepting integer subclasses returned by Construct. Supported revisions are explicitly 1, 2 and 3; revision 0 is intentionally rejected. This validates representability, not Tahoe ABI semantics. ProxyUtils initialization itself already performs device I/O before the run_guest guard.

`--single-core` retains the single observed running CPU, without assuming cpu0. Explicit CPU selections must retain that CPU and reference existing nodes. Legacy `-C 012` remains supported; comma syntax `-C 0,10` supports multi-digit IDs. A single multi-digit ID can use a trailing duplicate, e.g. `-C 10,10`, or preferably `--single-core` when it is the boot CPU. Selection still occurs after HV.init, so it cannot isolate initialization failures.

Flushed, address-free markers identify preflight-passed, hv-init-begin, hv-init-returned, bootargs-uploaded, image-loaded, entry-request and first-event. A marker proves only execution reached that point. In particular, entry-request precedes hv_start and first-event may be a routine emulation event, not a fault. Existing exception reporting remains responsible for fault details. These markers do not claim kernel output or boot success.

Regression tests import only the standalone validation helper and Construct types. Tests execute the actual AST-extracted guards with objects that have no device interface, round-trip all three real serializers, exercise CPU selection, and check first-event emits once. They do not execute HV initialization or emulate hardware.

```sh
M1N1_CHECKOUT=/path/to/patched/m1n1 python3 -m unittest discover -s tests -v
python3 scripts/guest_preflight.py --m1n1 /path/to/patched/m1n1
```

Use an environment with Construct installed. Loader tests skip without M1N1_CHECKOUT; a skipped run is not full validation. Validation was also performed after applying the patch to a separate clean checkout. The patch modifies Python host code only; the previously built C/Rust proxy binaries are unchanged. No hardware compatibility claim follows from these tests.

Revert with `git apply -R` against the same patch after checking for subsequent work. Preserve unrelated source changes.
