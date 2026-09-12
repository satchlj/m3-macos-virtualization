# Contributing

Start with the [project overview](docs/OVERVIEW.md) and
[current status](docs/STATUS.md). This is a research snapshot with substantial
host-side coverage, not a supported operating-system installation.

Maintainer: **Satya Benson** · [Contact](https://satchlj.com/contact).

## Useful contributions

- Improve documentation, diagrams, terminology, and links between claims and evidence.
- Add small synthetic fixtures for parsers, manifests, archive validation, and
  report formatting. These can be reviewed without private payloads or hardware.
- Improve error messages and input validation in independent host tools.
- Review the [code organization and maintenance backlog](docs/CODE-REVIEW.md).

Discuss large structural changes before combining them with changes to research
behavior. Preserve stable script paths and the distinction between the two
pinned m1n1 patch tracks.

## Local checks

Run commands from the repository root. The [test guide](tests/README.md) explains
which checks work in a fresh clone and which require patched upstream sources.

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_docs.py
git diff --check
```

A successful run with skipped tests is not full coverage. Include the Python
version, command, test count, skips, and any external prerequisites in your PR.
Tests under `tests/` run on the host; hardware runners live under `scripts/`.
Do not execute a hardware runner merely to validate a documentation change.

## Documentation changes

Use [STATUS.md](docs/STATUS.md) as the single current milestone summary. Historical
notes keep their original observations and failed hypotheses. Add a correction
or a link to later evidence when a hypothesis is resolved; do not silently turn
an old proposal into a successful result.

For a new result, record the scope, source/payload identity, evidence tier,
observed outcome, limitations, and the retained artifact reference. Add it to the
appropriate directory index. A public note referring to private evidence must
say what a fresh clone can and cannot independently verify.

Keep general setup instructions in [setup/README.md](setup/README.md), test
instructions in [tests/README.md](tests/README.md), and script descriptions in
[scripts/README.md](scripts/README.md). Avoid duplicating current status or
commands across several historical notes.

## Licensing and submitted material

Original contributions use MIT where permitted. The QEMU-derived layout module
retains GPL-2.0-or-later; consult [LICENSES.md](LICENSES.md) before copying code
or changing notices. Retain upstream authorship and record new third-party
provenance. Do not submit proprietary payloads, credentials, raw device trees,
or private captures; use small synthetic fixtures and the
[artifact policy](docs/artifact-storage.md).

A useful PR states the concrete problem, resulting behavior, checks performed,
and remaining limitations. A hardware result needs its own evidence review;
passing a replay does not establish that result.
