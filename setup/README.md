# Host environment setup

[Repository home](../README.md) · [Test guide](../tests/README.md)

For a first visit, start with the [fresh-clone host tests](../tests/README.md).
They do not need the full environment below. This page describes the existing
Apple Silicon macOS research setup; it is not a target installation guide.

## Reproduce the pinned source environment

Requirements: Apple Silicon macOS, Xcode Command Line Tools, Python 3.9+, Git,
and Homebrew. Python 3.14.7 was used for the documentation-review checks; the
stated minimum is not a tested version matrix.

Run from the repository root:

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

Bootstrap downloads source, initializes upstream submodules, and installs the two
pinned Python requirement lists. It does not install a target or obtain Apple
payloads. Builds are local artifacts; the [release review](../docs/PUBLIC-RELEASE-REVIEW.md)
does not approve distribution of those binaries or their embedded artwork.

| Path or variable | Purpose |
| --- | --- |
| `local/m1n1`, `M1N1_CHECKOUT` | Loader-validation source at `upstream.lock` |
| `local/m1n1-vel2`, `VEL2_CHECKOUT` | Experimental runtime source at `upstream-vel2.lock` |
| `local/venv` | Host/test Python environment |
| `local/payload-venv` | Separate payload extraction dependencies |
| `local/toolchains` | Toolchain state selected by the activation scripts |
| `ASAHI_ROOT` | Existing compatibility name for the local setup root |

The two patches are applied to separate upstream revisions. Bootstrap checks
patch hashes and selected source-file hashes before and after applying them. It
refuses an unexpected HEAD or mismatching recorded source hashes. These checks
are not an exhaustive dirty-tree audit: unlisted edits may exist in a reused
checkout. Use a separate setup root when preserving other work.

For an alternate setup root, pass `--root /absolute/path` to bootstrap and set
`ASAHI_ROOT` to that same path before sourcing `setup/activate.sh`. Activation
modifies the current shell environment, not your shell profile. Run all project
commands from this repository, even when the upstream trees live elsewhere.

## Common problems

| Symptom | What to check |
| --- | --- |
| Tests skip patched-source coverage | Activate the environment and check both checkout variables; see the test guide |
| `ModuleNotFoundError` in source-dependent tests | Use the host environment's Python and the pinned requirement list |
| Bootstrap reports source drift or unexpected HEAD | Preserve that checkout; choose a separate setup root |
| Compiler-dependent tests fail | Install the host C compiler supplied by Xcode Command Line Tools |
| Disassembly tests skip | Check the LLVM tools; those tests report their missing prerequisite |
| A historical command names a missing report or payload | Such inputs are excluded from Git; see the artifact policy |

[restore-payloads.py](restore-payloads.py) handles locally supplied evidence inputs;
its manifest contract is described in [artifact storage](../docs/artifact-storage.md).
A fresh clone contains no such inputs. No successful setup, build, or test run
establishes that a target is ready for experimental execution.
