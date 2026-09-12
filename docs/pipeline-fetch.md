# Fetching a pipeline attempt from the USB host

`fetch_pipeline_archive.py EXPERIMENT HOST:PATH/ATTEMPT.tar.gz` combines the
scp download and the [verified pipeline import](pipeline-import.md) into one
local command. It never opens a device or executes a guest; it only copies
two files over the existing authenticated ssh/scp alias and hands them to the
importer.

```sh
python scripts/fetch_pipeline_archive.py EXPERIMENT \
  user@usb-host:research/artifacts/runs/X/attempt.tar.gz
```

The remote spec must be `HOST:PATH/ATTEMPT.tar.gz` using only letters, digits,
`.`, `_`, `-`, `/` and one optional `user@`. Spaces, shell metacharacters, `.`
or `..` segments and option-like names are rejected before anything runs. scp
is invoked with a list argv and no shell.

The `.tar.gz.identity.json` sidecar is copied first, then the archive, into
`--archives` (default `artifacts/transfers/archives/`). Both land as hidden
partial files and are linked into place only after the archive's SHA-256 and
byte count match the sidecar. An existing local archive with the same identity
is reused and the copy is skipped; an existing archive or sidecar with a
different identity is refused and left untouched. Nothing is ever overwritten.

Extraction and catalog registration are the importer's `extract_verified` and
`register_pipeline`, with the same limits and `--max-expanded-bytes` override.
`--destination` must be new and defaults to `artifacts/runs/imports/ATTEMPT`;
`--store` defaults to `artifacts/catalog` and must already exist. The printed
JSON and `import-receipt.json` add a `transfer` block recording the remote
spec, local paths, digest, size and whether bytes were copied this time.

This does not claim the remote file is authentic; the sidecar checks transfer
integrity against what the USB host wrote. A mismatch, refused overwrite or
failed extraction leaves no destination and no catalog record. A catalog
failure after extraction keeps the extracted directory for investigation,
exactly as with the importer. `--scp-timeout` bounds each copy in seconds.
