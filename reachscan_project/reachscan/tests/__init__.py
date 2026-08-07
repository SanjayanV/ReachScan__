"""Test package bootstrap.

Adds the ReachScan package root to ``sys.path`` so that the absolute imports
used across the codebase (``from models import ...``, ``from config import ...``)
resolve regardless of how the test runner is invoked.
"""

import os
import sys

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)