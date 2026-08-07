"""The ReachScan scan pipeline (orchestration only).

Pipeline owns ordering and flow control; every step delegates to a focused
module. No vulnerability-detection logic lives here.
"""

from __future__ import annotations

from pathlib import Path

from config import Settings, load_settings
from utils.logging import get_logger
from utils.exceptions import ReachScanError
from core.parser.python import AstPythonParser
from core.graph import GraphBuilder, export_dot
from core.reachability import ReachabilityEngine
from core.reporting import HtmlReporter, JsonReporter
from core.scoring.severity import SEVERITY_ORDER
from providers import discover_manifests, get_provider
from models import Vulnerability

log = get_logger(__name__)

EXIT_OK = 0
EXIT_NO_SOURCE = 1
EXIT_ERROR = 2


class ScanEngine:
    """Coordinates the individual scan phases."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.parser = AstPythonParser(self.settings.parser.skip_dirs)
        self.graph_builder = GraphBuilder()
        self.reachability = ReachabilityEngine()
        self.html_reporter = HtmlReporter()
        self.json_reporter = JsonReporter()

    def run(self, args) -> int:
        root = Path(args.target).resolve()

        if not root.is_dir():
            log.error("Target directory does not exist: %s", root)
            return EXIT_ERROR

        parsed_modules = self.parser.parse_directory(root)
        if not parsed_modules:
            log.error("No Python source files found in %s", root)
            return EXIT_NO_SOURCE

        call_graph = self.graph_builder.build(parsed_modules)
        self._export_dot(args, call_graph)

        if args.graph_only:
            return EXIT_OK

        vulnerabilities = self._gather_vulnerabilities(args, root)
        vulnerabilities = self._apply_severity_filter(args, vulnerabilities)

        if not vulnerabilities:
            log.info("No vulnerabilities found. Dependencies appear clean.")
            return EXIT_OK

        results = self.reachability.analyze_many(vulnerabilities, call_graph)

        self._write_html(args, results, root, call_graph)
        self._write_json(args, results, root, call_graph)
        log.info("Reachable: %d · Unreachable: %d · Total: %d",
                 sum(1 for r in results if r.is_reachable),
                 sum(1 for r in results if not r.is_reachable),
                 len(results))
        return EXIT_OK

    # -- orchestration steps --------------------------------------------------

    def _gather_vulnerabilities(self, args, root: Path) -> list[Vulnerability]:
        provider = get_provider(
            "mock" if getattr(args, "no_network", False) else self.settings.providers.default
        )

        req_file = str(Path(args.req).resolve()) if args.req else None
        dependencies = discover_manifests(str(root), req_file)

        collected: dict[str, Vulnerability] = {}
        for dep in dependencies:
            try:
                found = provider.lookup(dep.name, dep.version)
            except ReachScanError as exc:
                log.warning("Provider lookup failed for %s: %s", dep.name, exc)
                continue
            dep.vulnerabilities = found
            for vuln in found:
                collected[vuln.osv_id or vuln.cve_id] = vuln

        log.info("Provider %s returned %d vulnerability record(s) from %d dependency(s)",
                 provider.name, len(collected), len(dependencies))
        return list(collected.values())

    def _apply_severity_filter(self, args,
                               vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        if not args.severity:
            return vulnerabilities
        threshold = SEVERITY_ORDER.get(args.severity, 3)
        kept = [v for v in vulnerabilities
                if SEVERITY_ORDER.get(v.severity, 4) <= threshold]
        log.info("Filtered to %d vulnerability(s) at %s+ severity", len(kept), args.severity)
        return kept

    def _export_dot(self, args, call_graph) -> None:
        dot_path = getattr(args, "dot", None)
        if not dot_path:
            return
        path = Path(dot_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(export_dot(call_graph), encoding="utf-8")
            log.info("DOT graph exported to %s", path)
        except OSError as exc:
            log.warning("Could not write DOT graph: %s", exc)

    def _write_html(self, args, results, root, call_graph) -> None:
        out = args.out or self.settings.report.html_output
        self.html_reporter.render(results, str(root), out, call_graph)

    def _write_json(self, args, results, root, call_graph) -> None:
        if not args.json:
            return
        base = args.out or self.settings.report.html_output
        json_path = str(Path(base).with_suffix(".json"))
        self.json_reporter.render(results, str(root), json_path, call_graph)


def run(args, settings: Settings | None = None) -> int:
    """Run the pipeline with the given parsed arguments; returns an exit code."""
    settings = settings or load_settings()
    engine = ScanEngine(settings)
    try:
        return engine.run(args)
    except ReachScanError as exc:
        log.error("%s", exc)
        return EXIT_ERROR