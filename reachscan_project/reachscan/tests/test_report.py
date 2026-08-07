"""Tests for the HTML and JSON reporters."""

import json
import unittest
from pathlib import Path

from core.reporting import HtmlReporter, JsonReporter
from tests.helpers import TempProject, make_vulnerability


class _FakeResults:
    """Minimal results derived from a Vulnerability for reporter tests."""

    def __init__(self, vulns):
        self.items = []
        for v in vulns:
            self.items.append(_FakeResult(v))

    def __iter__(self):
        return iter(self.items)


class _FakeResult:
    def __init__(self, vuln, reachable=True):
        self.vulnerability = vuln
        self.is_reachable = reachable
        self.reachable_via = ["sink"] if reachable else []
        self.execution_paths = [["main", "mid", "sink"]] if reachable else []
        self.unreachable_sinks = [] if reachable else ["sink"]
        self.missing_sinks = []
        self.match_confidence = 0.0
        self.priority = "CRITICAL"
        self.status = "REACHABLE" if reachable else "UNREACHABLE"

    def to_dict(self):
        return {
            "cve_id": self.vulnerability.cve_id,
            "package": self.vulnerability.package,
            "severity": self.vulnerability.severity,
            "priority": self.priority,
            "status": self.status,
            "is_reachable": self.is_reachable,
            "summary": self.vulnerability.summary,
            "vulnerable_functions": self.vulnerability.vulnerable_functions,
            "reachable_via": self.reachable_via,
            "execution_paths": self.execution_paths,
            "unreachable_sinks": self.unreachable_sinks,
            "missing_sinks": self.missing_sinks,
            "match_confidence": self.match_confidence,
            "cvss_score": self.vulnerability.cvss_score,
            "fixed_version": self.vulnerability.fixed_version,
            "references": self.vulnerability.references,
        }


class HtmlReporterTest(unittest.TestCase):
    def test_renders_without_leftover_placeholders(self):
        with TempProject() as p:
            results = _FakeResults([make_vulnerability("CVE-x", "demo")])
            out = str(p.root / "out" / "report.html")
            written = HtmlReporter().render(list(results), "target", out, None)
            html = Path(written).read_text()
            for token in ("{{TOTAL}}", "{{CARDS_HTML}}", "{{GRAPH_JSON}}",
                          "{{REACHABLE}}", "{{UNREACHABLE}}", "{{REDUCTION}}",
                          "{{TARGET_DIR}}", "{{TIMESTAMP}}"):
                self.assertNotIn(token, html)

    def test_creates_parent_directory(self):
        with TempProject() as p:
            out = str(p.root / "nested" / "dir" / "r.html")
            written = HtmlReporter().render([], "target", out, None)
            self.assertTrue(Path(written).exists())


class JsonReporterTest(unittest.TestCase):
    def test_output_shape(self):
        with TempProject() as p:
            results = list(_FakeResults([make_vulnerability("CVE-y", "demo")]))
            out = str(p.root / "r.json")
            written = JsonReporter().render(results, "t", out, None)
            data = json.loads(Path(written).read_text())
            self.assertEqual(data["summary"]["total_cves"], 1)
            self.assertEqual(data["vulnerabilities"][0]["cve_id"], "CVE-y")


if __name__ == "__main__":
    unittest.main()