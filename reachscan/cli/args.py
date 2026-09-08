"""Command-line argument parsing.

Kept separate from the pipeline so the CLI surface can evolve without
touching orchestration logic.
"""

from __future__ import annotations

import argparse

SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ReachScan v2.0 — Context-aware dependency vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="Path to the Python project directory")
    parser.add_argument(
        "--req", default=None,
        help="Path to requirements.txt (default: <target>/requirements.txt)",
    )
    parser.add_argument(
        "--out", default=None,
        help="Output path for HTML report (default: config.report.html)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also write JSON results file",
    )
    parser.add_argument(
        "--no-network", action="store_true",
        help="Skip the live provider and use the mock (offline/demo mode)",
    )
    parser.add_argument(
        "--severity", default=None, choices=SEVERITY_CHOICES,
        help="Minimum severity threshold to report",
    )
    parser.add_argument(
        "--graph-only", action="store_true",
        help="Only build call graph, skip vulnerability scanning",
    )
    parser.add_argument(
        "--dot", default=None,
        help="Export call graph in DOT format to this path",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=True, dest="verbose",
        help="Enable DEBUG-level logging (on by default)",
    )
    return parser


def parse_args(args=None) -> argparse.Namespace:
    return build_parser().parse_args(args)