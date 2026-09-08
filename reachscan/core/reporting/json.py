"""Serialise analysis results to a JSON document."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from utils.logging import get_logger
from utils.exceptions import ReportError
from core.graph.exporter import export_graph_summary
from core.reporting.base import Reporter
from models.graph import CallGraph
from models.result import ReachabilityResult

log = get_logger(__name__)

VERSION = "2.0"


class JsonReporter(Reporter):
    """Writes the full set of results plus a call-graph summary to JSON."""

    def __init__(self, engine_version: str = VERSION):
        self.engine_version = engine_version

    def render(self, results: list[ReachabilityResult],
               target_dir: str,
               output_path: str | None,
               call_graph: CallGraph | None) -> str:
        graph_summary = export_graph_summary(call_graph) if call_graph else {"nodes": [], "edges": []}
        output_data = {
            "meta": {
                "target": os.path.abspath(target_dir),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "engine": f"ReachScan v{self.engine_version}",
            },
            "summary": {
                "total_cves": len(results),
                "reachable": sum(1 for r in results if r.is_reachable),
                "unreachable": sum(1 for r in results if not r.is_reachable),
            },
            "vulnerabilities": [r.to_dict() for r in results],
            "call_graph": graph_summary,
        }

        out = output_path or "report.json"
        try:
            out_path = Path(out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"Could not write JSON report: {exc}") from exc

        log.info("JSON report written to %s", out)
        return str(out_path)