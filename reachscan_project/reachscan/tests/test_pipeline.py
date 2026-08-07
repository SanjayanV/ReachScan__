"""End-to-end pipeline test against a temporary vulnerable project."""

import json
import unittest
from pathlib import Path

from cli.args import parse_args
from cli.pipeline import run, EXIT_OK
from tests.helpers import TempProject

VULN_APP = {
    "requirements.txt": "PyYAML==5.3.1\n",
    "app.py": """\
import yaml

def main():
    run_pipeline()

def run_pipeline():
    load_config()

def load_config():
    return yaml.load(open('c'))

if __name__ == "__main__":
    main()
""",
}


class PipelineTest(unittest.TestCase):
    def test_offline_pipeline_writes_html_and_json(self):
        with TempProject() as p:
            for name, content in VULN_APP.items():
                p.write(name, content)
            args = parse_args([str(p.root), "--no-network", "--json",
                               "--out", str(p.root / "report.html")])
            code = run(args)
            self.assertEqual(code, EXIT_OK)
            self.assertTrue((p.root / "report.html").exists())
            self.assertTrue((p.root / "report.json").exists())
            data = json.loads((p.root / "report.json").read_text())
            self.assertTrue(data["vulnerabilities"])  # mock data present

    def test_graph_only_skips_vulns(self):
        with TempProject() as p:
            for name, content in VULN_APP.items():
                p.write(name, content)
            args = parse_args([str(p.root), "--graph-only"])
            self.assertEqual(run(args), EXIT_OK)

    def test_missing_target_is_error(self):
        with TempProject() as p:
            args = parse_args([str(p.root / "does-not-exist")])
            self.assertEqual(run(args), 2)

    def test_severity_filter(self):
        with TempProject() as p:
            for name, content in VULN_APP.items():
                p.write(name, content)
            args = parse_args([str(p.root), "--no-network", "--severity", "CRITICAL",
                               "--out", str(p.root / "r.html"), "--json"])
            run(args)
            data = json.loads((p.root / "r.json").read_text())
            # Only the CRITICAL PyYAML advisory survives the filter.
            self.assertEqual(data["summary"]["total_cves"], 1)
            self.assertEqual(data["vulnerabilities"][0]["severity"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()