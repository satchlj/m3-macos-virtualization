#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check local Markdown paths and navigation without fetching links or running code.

Checks inline Markdown links, documentation reachability from README.md, and
scripts/README.md coverage. URL destinations and heading fragments are not
validated. This is deliberately a repository navigation check, not a Markdown
renderer or a claim that the documented commands work.
"""
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit


LINK = re.compile(r"\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)")


def local_links(path):
    """Yield inline local link paths, excluding fenced examples and external URLs."""
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in LINK.finditer(line):
            value = match.group(1).strip("<>")
            url = urlsplit(value)
            if not url.scheme and not url.netloc and url.path:
                yield unquote(url.path)


def check(root, files):
    """Return navigation errors for an explicit repository-relative file list."""
    root = root.resolve()
    included = {root / name for name in files}
    markdown = {path for path in included if path.suffix == ".md"}
    graph = {}
    errors = []
    for source in sorted(markdown):
        destinations = set()
        for link in local_links(source):
            target = (source.parent / link).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                errors.append(f"{source.relative_to(root)}: link leaves repository: {link}")
                continue
            if not target.exists():
                errors.append(f"{source.relative_to(root)}: missing path: {link}")
            elif target.is_file() and target not in included:
                errors.append(f"{source.relative_to(root)}: path is not in source listing: {link}")
            elif target.is_dir() and not any(target in path.parents for path in included):
                errors.append(f"{source.relative_to(root)}: directory has no included files: {link}")
            destinations.add(target)
        graph[source] = destinations

    reached = set()
    pending = [root / "README.md"]
    while pending:
        source = pending.pop()
        if source in reached:
            continue
        reached.add(source)
        pending.extend((graph.get(source, set()) & markdown) - reached)
    for path in sorted(markdown):
        if path not in reached:
            errors.append(f"Unreachable Markdown: {path.relative_to(root)}")

    indexed_scripts = graph.get(root / "scripts/README.md", set())
    for name in sorted(files):
        if name.startswith("scripts/") and name.endswith(".py"):
            if root / name not in indexed_scripts:
                errors.append(f"Script missing from scripts/README.md: {name}")
    return errors


def main():
    root = Path(__file__).resolve().parents[1]
    listing = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root,
    ).decode("utf-8")
    files = sorted(set(listing.rstrip("\0").split("\0")))
    errors = check(root, files)
    if errors:
        print("\n".join(errors))
        return 1
    count = sum(name.endswith(".md") for name in files)
    print(f"Documentation OK: {count} Markdown files reachable; local paths and script index checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
