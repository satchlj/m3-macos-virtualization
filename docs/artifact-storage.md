# Local artifact storage

Bulk and proprietary artifacts are intentionally excluded from Git. Keep code,
concise findings, small synthetic fixtures, and content hashes in the repository;
put payloads, raw traces, generated reports, and build outputs under the ignored
`artifacts/` or `local/` trees.

Recommended layout:

| Directory | Contents |
| --- | --- |
| `artifacts/evidence/` | Locally obtained payloads, original captures, and checksum manifests |
| `artifacts/catalog/` | Experiment database and content-addressed objects |
| `artifacts/runs/` | Immutable attempt directories and reports |
| `artifacts/transfers/archives/` | Closed pipeline archives and identity sidecars |
| `artifacts/backups/` | Verified catalog backups |
| `local/m1n1*` | Reproducible upstream checkouts created by bootstrap |
| `local/payload/` | Disposable extracted inputs |

A fresh clone contains none of these artifacts. To recreate local payloads from
inputs you are entitled to use, prepare `sha256.json` beside the payload files and
run:

```sh
python setup/restore-payloads.py --evidence /path/to/evidence
```

The restoration tool verifies every manifest digest before extraction. It does
not download payloads. Some historical replay tests skip when their optional raw
evidence is absent; the small fixtures in `tests/fixtures/` still exercise the
control path.

Never commit Apple payloads, raw device trees, full traces containing machine
identifiers, credentials, private keys, serial device paths, or build outputs.
