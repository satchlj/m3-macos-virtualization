"""Regression coverage for the repository's offline navigation checker."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_docs import check


class DocumentationNavigationTests(unittest.TestCase):
    def review(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            return check(root, list(files))

    def test_connected_cycle_and_url_are_valid(self):
        self.assertEqual(self.review({
            "README.md": "[Guide](docs/guide.md#heading) [Web](https://example.invalid/x)",
            "docs/guide.md": "[Home](../README.md)",
        }), [])

    def test_disconnected_cycle_is_unreachable(self):
        errors = self.review({
            "README.md": "Home", "docs/a.md": "[B](b.md)",
            "docs/b.md": "[A](a.md)",
        })
        self.assertEqual(len(errors), 2)
        self.assertTrue(all("Unreachable Markdown" in error for error in errors))

    def test_missing_path_and_escape_are_reported(self):
        errors = self.review({"README.md": "[Missing](docs/missing.md) [Escape](../outside.md)"})
        self.assertEqual(len(errors), 2)
        self.assertIn("missing path", errors[0])
        self.assertIn("leaves repository", errors[1])

    def test_fenced_examples_ignored_and_spaces_supported(self):
        self.assertEqual(self.review({
            "README.md": "```md\n[Example](missing.md)\n```\n[Guide](<docs/My Guide.md>)",
            "docs/My Guide.md": "Guide",
        }), [])

    def test_script_requires_index_entry(self):
        files = {"README.md": "[Scripts](scripts/README.md)",
                 "scripts/README.md": "Scripts", "scripts/tool.py": ""}
        self.assertEqual(self.review(files), ["Script missing from scripts/README.md: scripts/tool.py"])
        files["scripts/README.md"] = "[Tool](tool.py)"
        self.assertEqual(self.review(files), [])

    def test_local_private_file_does_not_count_as_a_publishable_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("[Private](private.md)")
            (root / "private.md").write_text("Not in the source listing")
            errors = check(root, ["README.md"])
            self.assertEqual(errors, ["README.md: path is not in source listing: private.md"])
