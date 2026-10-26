import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import anonymize


class JavaAuthorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.map_path = Path(self.temp.name) / "map.anon"

    def run_cli(self, command, *args):
        result = subprocess.run(
            [sys.executable, str(Path(anonymize.__file__)), command,
             "--map", str(self.map_path), *map(str, args)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_repeated_authors_and_other_terms_round_trip(self):
        originals = {
            "A.java": "/**\n@author MARIO ROSSI\n**/\nCompany\n",
            "B.java": "/**\n * @author MARIO ROSSI\n * @author JANE DOE\n */\n",
        }
        for name, text in originals.items():
            (self.root / name).write_text(text)
        self.run_cli("anonymize", "--folder", self.root, "--terms", "Company")
        pairs = dict(anonymize._load_map(self.map_path))
        self.assertEqual(set(pairs), {"@author MARIO ROSSI", "@author JANE DOE", "Company"})
        for name, original in originals.items():
            expected = original
            for term, token in pairs.items():
                self.assertTrue(token.startswith("__M_ANON_"))
                expected = expected.replace(term, token)
            self.assertEqual((self.root / name).read_text(), expected)
        token = self.run_cli("encode", "@author MARIO ROSSI")
        self.assertEqual(token, pairs["@author MARIO ROSSI"])
        self.assertEqual(self.run_cli("decode", token), "@author MARIO ROSSI")
        self.run_cli("restore", "--folder", self.root)
        for name, original in originals.items():
            self.assertEqual((self.root / name).read_text(), original)

    def test_single_file_preserves_crlf_and_inline_comment_closers(self):
        path = self.root / "A.java"
        original = b"/** @author MARIO ROSSI **/\r\n/**\r\n * @author JANE DOE  \r\n */\r\n"
        path.write_bytes(original)
        self.run_cli("anonymize", "--file", path)
        pairs = dict(anonymize._load_map(self.map_path))
        self.assertEqual(set(pairs), {"@author MARIO ROSSI", "@author JANE DOE"})
        expected = original
        for term, token in pairs.items():
            expected = expected.replace(term.encode(), token.encode())
        self.assertEqual(path.read_bytes(), expected)
        self.run_cli("restore", "--file", path)
        self.assertEqual(path.read_bytes(), original)

    def test_incremental_runs_reuse_tokens_in_new_files(self):
        original = "/** @author MARIO ROSSI */"
        first = self.root / "A.java"
        first.write_text(original)
        self.run_cli("anonymize", "--folder", self.root)
        pairs = anonymize._load_map(self.map_path)
        self.run_cli("anonymize", "--folder", self.root)
        second = self.root / "B.java"
        second.write_text(original)
        self.run_cli("anonymize", "--folder", self.root)
        self.assertEqual(anonymize._load_map(self.map_path), pairs)
        self.assertEqual(first.read_text(), second.read_text())
        self.run_cli("restore", "--folder", self.root)
        self.assertEqual(first.read_text(), original)
        self.assertEqual(second.read_text(), original)

    def test_discovery_skips_non_java_binary_and_excluded_directories(self):
        (self.root / "notes.txt").write_text("@author TEXT AUTHOR")
        (self.root / "Binary.java").write_bytes(b"\x00@author BINARY AUTHOR")
        skipped = self.root / "target"
        skipped.mkdir()
        (skipped / "Generated.java").write_text("@author GENERATED AUTHOR")
        (self.root / "A.java").write_text("/** @author REAL AUTHOR */")
        self.run_cli("anonymize", "--folder", self.root)
        self.assertEqual(set(dict(anonymize._load_map(self.map_path))), {"@author REAL AUTHOR"})
        self.assertEqual((self.root / "notes.txt").read_text(), "@author TEXT AUTHOR")

    def test_overlapping_terms_and_case_variants_restore_exactly(self):
        path = self.root / "A.java"
        original = "/** @author MARIO ROSSI */\n/** @author Mario Rossi */\nMARIO ROSSI"
        path.write_text(original)
        self.run_cli("anonymize", "--file", path, "--terms", "MARIO ROSSI", "--ignore-case")
        pairs = dict(anonymize._load_map(self.map_path))
        self.assertIn("@author MARIO ROSSI", pairs)
        self.assertIn("@author Mario Rossi", pairs)
        self.assertNotEqual(pairs["@author MARIO ROSSI"], pairs["@author Mario Rossi"])
        self.assertNotIn("@author", path.read_text())
        self.run_cli("restore", "--file", path)
        self.assertEqual(path.read_text(), original)


if __name__ == "__main__":
    unittest.main()
