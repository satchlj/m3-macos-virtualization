# M3 Tahoe SPTM virtualization research

Experimental tooling for running and observing Tahoe's SPTM/TXM/XNU path on an
Apple M3 (J613/T8122) through a patched
[Asahi Linux m1n1](https://github.com/AsahiLinux/m1n1) hypervisor.

This repository is a research snapshot, not a macOS boot solution. It contains
host tooling, tests, two pinned m1n1 patch series, and concise technical notes. It
does **not** contain Apple firmware, kernel collections, device trees, raw traces,
credentials, or a prebuilt boot image.

## Current result

On 2026-09-11, source- and live-byte-verified hardware runs completed XNU
Phase 5.3 allocation and page-table-frame retype sequences on M3/J613:

- XNU entered the allocation call and returned an owned 16 KiB physical page.
- One transaction changed an authoritative SPTM frame record from
  `XNU_DEFAULT` (`0x0b`) to `TXM_DEFAULT` (`0x29`).
- A following bounded survey observed four intermediate retypes and stopped on
  an exact `XNU_DEFAULT` to `XNU_PAGE_TABLE` (`0x14`) transition with flags `3`.
- Each selector-1 `genter` completed its XNU/SPTM round trip and returned to the
  authenticated XNU wrapper path.
- The bounded run returned cleanly and the m1n1 proxy remained responsive.

This is meaningful dynamic-memory-service progress, but it does **not** establish
a general allocator, a runtime Stage-1 descriptor mutation, kernel bring-up,
macOS boot, or GPU support.
See [project status](docs/STATUS.md) for the roadmap and evidence boundary.

## Reproduce the host environment

Requirements: Apple Silicon macOS, Xcode Command Line Tools, Python 3.9+, Git,
and Homebrew packages `llvm`, `lld`, `rustup`, and GNU `make`.

```sh
brew install llvm lld rustup make
python3 setup/bootstrap.py
source setup/activate.sh
rustup toolchain install 1.98.1 --profile minimal
rustup target add --toolchain 1.98.1 aarch64-unknown-none-softfloat
python -m unittest discover -s tests -v
make -C "$M1N1_CHECKOUT" -j4
make -C "$VEL2_CHECKOUT" -j4
```

`setup/bootstrap.py` clones two independent pinned m1n1 revisions under the
ignored `local/` directory, verifies patch hashes, applies each patch only to its
matching base, initializes submodules, and creates locked Python environments.
It refuses to overwrite a checkout with unexpected changes.

The two patch tracks are intentionally separate:

- `0001-validate-guest-setup-and-report-stages.patch` adds conservative loader
  validation and stage reporting to the original loader track.
- `0002-experimental-virtual-el2.patch` adds the experimental virtual-EL2 runtime,
  bounded trace/filter firmware paths, and proxy API to the research track.

The checked-in test suite is host-only unless an individual command explicitly
documents an `--execute` gate. A passing build or synthetic replay is not evidence
that a target is safe to run or that Tahoe boots.

## Repository map

- [`patches/m1n1/`](patches/m1n1/) — pinned patches against exact upstream
  revisions in `upstream*.lock`.
- [`scripts/`](scripts/) — offline decoders/replayers plus explicitly gated
  hardware runners.
- [`tests/`](tests/) — unit and synthetic end-to-end regression coverage.
- [`docs/`](docs/) — curated architecture, evidence, and experiment notes.
- [`setup/`](setup/) — reproducible checkout and Python environment setup.

Start with the [documentation index](docs/README.md), then read the
[safety/evidence rules](docs/SAFETY.md) before considering hardware work.

## Inputs and provenance

Apple payloads are intentionally excluded. `setup/restore-payloads.py` accepts a
locally supplied, checksum-manifested evidence directory and recreates disposable
extracted payloads under ignored `local/payload/`. It neither downloads nor
redistributes proprietary inputs.

The lock files identify exact upstream repositories, commits, expected source
hashes, and patch hashes. See [licensing and provenance](LICENSES.md) before
redistribution; this snapshot does not yet declare a project-wide license for all
unmarked files.
