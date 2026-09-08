"""Shared test fixtures and helpers."""

from __future__ import annotations

import tempfile
from pathlib import Path


class TempProject:
    """A throwaway directory we can write source files into."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False

    def write(self, relpath: str, content: str):
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return self

    def cleanup(self) -> None:
        self._tmp.cleanup()


def make_vulnerability(cve_id="CVE-0000-0000", package="demo", severity="HIGH",
                       vulnerable_functions=None) -> object:
    from models import Vulnerability
    return Vulnerability(
        cve_id=cve_id,
        package=package,
        severity=severity,
        summary="demo",
        affected_versions=["1.0.0"],
        vulnerable_functions=vulnerable_functions or [f"{package}.sink"],
        osv_id=f"GHSA-{cve_id}",
    )