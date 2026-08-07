"""Tests for resolver helpers: imports, sinks and sink matching."""

import unittest

from core.resolver.sinks import get_vulnerable_functions, KNOWN_SINK_SIGNATURES
from core.resolver.imports import get_import_names
from core.resolver.matching import match_score


class ImportNamesTest(unittest.TestCase):
    def test_alias_mapping(self):
        names = get_import_names("pyyaml")
        self.assertIn("yaml", names)

    def test_dash_to_underscore(self):
        self.assertIn("scikit_learn", get_import_names("scikit-learn"))
        self.assertIn("scikit_learn", get_import_names("scikit-learn"))


class SinksTest(unittest.TestCase):
    def test_known_signature(self):
        funcs = get_vulnerable_functions("PyYAML")
        self.assertIn("yaml.load", funcs)

    def test_hints_from_text(self):
        funcs = get_vulnerable_functions("somepkg", "uses `foo.bar()` and `baz()` here")
        self.assertIn("foo.bar", funcs)
        self.assertIn("baz", funcs)

    def test_fallback_package_wildcard(self):
        funcs = get_vulnerable_functions("mystery")
        self.assertEqual(funcs, ["mystery.*"])


class MatchingTest(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(match_score("yaml.load", "yaml.load", "PyYAML"), 1.0)

    def test_case_insensitive(self):
        self.assertAlmostEqual(match_score("Image.open", "image.open", "Pillow"), 0.95)

    def test_root_mismatch_blocks_cross_package(self):
        # numpy.load must NOT match yaml.load
        self.assertEqual(match_score("yaml.load", "numpy.load", "numpy"), 0.0)

    def test_shortname_below_threshold(self):
        self.assertLess(match_score("open", "Image.open", "Pillow"), 0.30)


if __name__ == "__main__":
    unittest.main()