"""Tests for severity parsing and classification."""

import unittest

from core.scoring.severity import (
    SEVERITY_ORDER,
    parse_cvss_score,
    score_to_severity,
    extract_severity,
)


class ParseCvssTest(unittest.TestCase):
    def test_numeric_string(self):
        self.assertEqual(parse_cvss_score("9.8"), 9.8)

    def test_vector_without_numeric_token_returns_zero(self):
        # A bare CVSS vector carries no numeric score token; the original
        # engine could not score it either, so we keep returning 0.0.
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self.assertEqual(parse_cvss_score(vec), 0.0)

    def test_empty_returns_zero(self):
        self.assertEqual(parse_cvss_score(""), 0.0)


class ScoreToSeverityTest(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(score_to_severity(9.5), "CRITICAL")
        self.assertEqual(score_to_severity(7.5), "HIGH")
        self.assertEqual(score_to_severity(5.5), "MEDIUM")
        self.assertEqual(score_to_severity(2.5), "LOW")
        self.assertEqual(score_to_severity(0.0), "UNKNOWN")


class ExtractSeverityTest(unittest.TestCase):
    def test_from_database_specific_severity(self):
        entry = {"database_specific": {"severity": "CRITICAL"},
                 "severity": [{"type": "CVSS_V3",
                               "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        sev, score, _ = extract_severity(entry)
        self.assertEqual(sev, "CRITICAL")
        self.assertGreater(score, 0.0)

    def test_alias_fallback(self):
        entry = {"aliases": ["CVE-2020-1234"], "severity": []}
        sev, score, _ = extract_severity(entry)
        self.assertEqual(sev, "HIGH")
        self.assertEqual(score, 7.0)


class OrderTest(unittest.TestCase):
    def test_order(self):
        self.assertLess(SEVERITY_ORDER["CRITICAL"], SEVERITY_ORDER["HIGH"])
        self.assertLess(SEVERITY_ORDER["LOW"], SEVERITY_ORDER["UNKNOWN"])


if __name__ == "__main__":
    unittest.main()