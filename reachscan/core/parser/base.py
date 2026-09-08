"""Language parser interface.

A parser turns a directory of source files into ``ParsedModule`` objects.
Only the Python implementation ships today; adding Java/Go/JS support means
implementing this small interface, not touching the rest of the engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from models.code import ParsedModule


class LanguageParser(ABC):
    """Contract implemented by any source-code parser."""

    @abstractmethod
    def parse_file(self, file_path: str | Path) -> ParsedModule | None:
        """Parse a single source file.

        Returns ``None`` when the file cannot be parsed so that a scanner
        can continue with the remaining files.
        """

    @abstractmethod
    def parse_directory(self, directory: str | Path) -> list[ParsedModule]:
        """Parse every supported source file under ``directory``."""