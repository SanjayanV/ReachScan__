#!/usr/bin/env python3
"""
ReachScan v2.0 — thin CLI entry point.

This file wires together argument parsing, configuration and the scan
pipeline. All business logic lives under cli/, core/, providers/ and models/.
"""

import sys

from config import load_settings
from utils.logging import configure_logging
from cli import parse_args
from cli.pipeline import run


def main() -> int:
    args = parse_args()
    settings = load_settings()
    configure_logging(settings, level="DEBUG" if args.verbose else None)
    return run(args, settings)


if __name__ == "__main__":
    sys.exit(main())