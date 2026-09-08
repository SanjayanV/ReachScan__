"""Tests for the AST Python parser."""

import unittest

from core.parser.python import AstPythonParser
from tests.helpers import TempProject

SAMPLE = """
import yaml
from jinja2 import Environment

def load_config(path):
    return yaml.load(open(path))

@app.route('/')
def entry():
    return run_pipeline('x')

def run_pipeline(data):
    return process()

def process():
    return Environment()

if __name__ == "__main__":
    entry()
"""


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.p = TempProject()
        self.p.write("mod.py", SAMPLE)
        self.parser = AstPythonParser(skip_dirs={"__pycache__", ".git"})

    def tearDown(self):
        self.p.cleanup()

    def test_parses_file(self):
        mod = self.parser.parse_file(self.p.root / "mod.py")
        self.assertIsNotNone(mod)

    def test_function_and_call_extraction(self):
        mod = self.parser.parse_file(self.p.root / "mod.py")
        fnames = [f.name for f in mod.functions]
        self.assertIn("load_config", fnames)
        self.assertIn("entry", fnames)
        # entry point detected via @app.route decorator
        entry = next(f for f in mod.functions if f.name == "entry")
        self.assertTrue(entry.is_entry_point)

    def test_entry_point_by_decorator(self):
        mod = self.parser.parse_file(self.p.root / "mod.py")
        entry = next(f for f in mod.functions if f.name == "entry")
        self.assertTrue(any("route" in d for d in entry.decorators))

    def test_skip_directories(self):
        self.p.write("__pycache__/junk.py", "x = 1\n")
        mods = self.parser.parse_directory(self.p.root)
        self.assertEqual(len(mods), 1)

    def test_syntax_error_returns_none(self):
        self.p.write("bad.py", "def f(:\n")
        self.assertIsNone(self.parser.parse_file(self.p.root / "bad.py"))


if __name__ == "__main__":
    unittest.main()