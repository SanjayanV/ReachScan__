#!/usr/bin/env python3
"""
ReachScan v2.0 — Automated Reachability Analysis for Dependency Security
"""

import sys
import os
import json
import argparse
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.ingestion import run_ingestion, Vulnerability
from modules.parser import parse_directory
from modules.graph import build_call_graph, export_graph_summary, export_dot
from modules.reachability import run_reachability_analysis
from modules.reporter import generate_html_report

VERSION = "2.0"

BANNER = r"""
  ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝█████╗  ███████║██║     ███████║███████╗██║     ███████║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║╚════██║██║     ██╔══██║██║╚██╗██║
  ██║  ██║███████╗██║  ██║╚██████╗██║  ██║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  Automated Reachability Analysis for Dependency Security  v2.0
  Static Call Graph · OSV.dev · Package-Aware Sink Matching
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReachScan v2.0 — Context-aware dependency vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Path to the Python project directory")
    parser.add_argument("--req", default=None,
                        help="Path to requirements.txt (default: <target>/requirements.txt)")
    parser.add_argument("--out", default="reports/report.html",
                        help="Output path for HTML report")
    parser.add_argument("--json", action="store_true",
                        help="Also write JSON results file")
    parser.add_argument("--no-network", action="store_true",
                        help="Skip OSV API (offline/demo mode)")
    parser.add_argument("--severity", default=None, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity threshold to report")
    parser.add_argument("--graph-only", action="store_true",
                        help="Only build call graph, skip vulnerability scanning")
    parser.add_argument("--dot", default=None,
                        help="Export call graph in DOT format to this path")
    parser.add_argument("-v", "--verbose", action="store_true", default=True)

    return parser.parse_args()


def inject_demo_vulns(deps):
    mock_vulns = [
        Vulnerability(
            cve_id="CVE-2020-14343", package="PyYAML", severity="CRITICAL",
            summary="PyYAML yaml.load() without Loader is susceptible to arbitrary code execution via a crafted YAML payload.",
            affected_versions=["5.3.1"],
            vulnerable_functions=["yaml.load", "yaml.unsafe_load"],
            osv_id="GHSA-8q59-q68h-6hv4",
            cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            fixed_version="5.4",
            references=["https://github.com/yaml/pyyaml/issues/420"],
        ),
        Vulnerability(
            cve_id="CVE-2022-22817", package="Pillow", severity="HIGH",
            summary="Pillow PIL.Image.open is vulnerable to a decompression bomb attack leading to denial of service.",
            affected_versions=["9.0.0"],
            vulnerable_functions=["Image.open", "Image.frombuffer"],
            osv_id="GHSA-4fx9-hhprp-fxc3",
            cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            fixed_version="9.0.1",
            references=["https://pillow.readthedocs.io/en/stable/releasenotes/9.0.1.html"],
        ),
        Vulnerability(
            cve_id="CVE-2024-34064", package="Jinja2", severity="MEDIUM",
            summary="Jinja2 Template rendering is vulnerable to XSS via the xmlattr filter when keys contain certain characters.",
            affected_versions=["3.0.0"],
            vulnerable_functions=["Template", "Environment"],
            osv_id="GHSA-h75v-3vvj-5mfj",
            cvss_score=5.4, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            fixed_version="3.1.4",
            references=["https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj"],
        ),
        Vulnerability(
            cve_id="CVE-2023-32681", package="requests", severity="MEDIUM",
            summary="Requests library forwards proxy-authorization headers to destination servers, leaking credentials.",
            affected_versions=["2.28.0"],
            vulnerable_functions=["requests.get", "requests.post", "requests.Session"],
            osv_id="GHSA-j8r2-6x86-q33q",
            cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
            fixed_version="2.31.0",
            references=["https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"],
        ),
        Vulnerability(
            cve_id="CVE-2021-41496", package="numpy", severity="HIGH",
            summary="NumPy numpy.load with allow_pickle=True is vulnerable to arbitrary code execution through crafted .npy files.",
            affected_versions=["1.21.0"],
            vulnerable_functions=["numpy.load", "numpy.fromstring"],
            osv_id="GHSA-fpfv-jqm9-f5jm",
            cvss_score=7.8, cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            fixed_version="1.22.0",
            references=["https://github.com/numpy/numpy/issues/19000"],
        ),
    ]
    return mock_vulns


def main():
    args = parse_args()
    t_start = time.time()

    print(BANNER)
    print(f"  Target    : {os.path.abspath(args.target)}")
    req_file = args.req or os.path.join(args.target, "requirements.txt")
    print(f"  Manifest  : {req_file}")
    print(f"  Report    : {args.out}")
    print(f"  Network   : {'OFF (demo mode)' if args.no_network else 'ON (OSV.dev API)'}")
    if args.severity:
        print(f"  Threshold : {args.severity}+")
    print()

    all_vulns = []
    if not args.graph_only:
        if args.no_network:
            print("\n╔══════════════════════════════════════════════╗")
            print("║   MODULE 1: Vulnerability Ingestion Engine   ║")
            print("╚══════════════════════════════════════════════╝")
            print("\n  [*] Offline mode: using mock vulnerability database...")
            from modules.ingestion import parse_requirements
            deps = parse_requirements(req_file)
            all_vulns = inject_demo_vulns(deps)
            print(f"  [✓] Loaded {len(all_vulns)} mock CVEs for demonstration.")
        else:
            deps, all_vulns = run_ingestion(req_file, verbose=args.verbose)

        if args.severity and all_vulns:
            threshold = SEVERITY_ORDER.get(args.severity, 3)
            all_vulns = [v for v in all_vulns
                         if SEVERITY_ORDER.get(v.severity, 4) <= threshold]
            print(f"\n  [*] Filtered to {len(all_vulns)} CVEs at {args.severity}+ severity")

    parsed_modules = parse_directory(args.target, verbose=args.verbose)

    if not parsed_modules:
        print("\n  [!] No Python source files found in target directory.")
        sys.exit(1)

    call_graph = build_call_graph(parsed_modules, verbose=args.verbose)

    if args.dot:
        dot_str = export_dot(call_graph)
        os.makedirs(os.path.dirname(args.dot) if os.path.dirname(args.dot) else ".", exist_ok=True)
        with open(args.dot, "w") as f:
            f.write(dot_str)
        print(f"\n  [✓] DOT graph exported to: {args.dot}")

    if args.graph_only:
        elapsed = time.time() - t_start
        print(f"\n  ⏱  Graph-only mode completed in {elapsed:.2f}s")
        return

    if not all_vulns:
        print("\n  ✅ No vulnerabilities found. Your dependencies are clean!")
        return

    results = run_reachability_analysis(all_vulns, call_graph, verbose=args.verbose)

    print("\n╔══════════════════════════════════════════════╗")
    print("║           Report Generation                  ║")
    print("╚══════════════════════════════════════════════╝\n")

    out_path = generate_html_report(
        results=results,
        target_dir=os.path.abspath(args.target),
        output_path=args.out,
        call_graph=call_graph,
    )
    print(f"  [✓] HTML report written to: {out_path}")

    if args.json:
        json_path = args.out.replace(".html", ".json")
        graph_summary = export_graph_summary(call_graph)
        output_data = {
            "meta": {
                "target": os.path.abspath(args.target),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "engine": f"ReachScan v{VERSION}",
            },
            "summary": {
                "total_cves": len(results),
                "reachable": sum(1 for r in results if r.is_reachable),
                "unreachable": sum(1 for r in results if not r.is_reachable),
            },
            "vulnerabilities": [r.to_dict() for r in results],
            "call_graph": graph_summary,
        }
        os.makedirs(os.path.dirname(json_path) if os.path.dirname(json_path) else ".", exist_ok=True)
        with open(json_path, "w") as f:
            json.dump(output_data, f, indent=2)
        print(f"  [✓] JSON results written to: {json_path}")

    elapsed = time.time() - t_start
    print(f"\n  ⏱  Analysis completed in {elapsed:.2f}s")
    print()


if __name__ == "__main__":
    main()
