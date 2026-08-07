"""Reporter interface.

A reporter turns the analysis results into an artefact (HTML, JSON, ...).
Adding a new output format means implementing this interface without touching
the scan pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from models.graph import CallGraph
from models.result import ReachabilityResult


class Reporter(ABC):
    """Contract implemented by every output format."""

    @abstractmethod
    def render(self, results: list[ReachabilityResult],
               target_dir: str,
               output_path: str | None,
               call_graph: CallGraph | None) -> str:
        """Serialize results to a file and return the written path."""