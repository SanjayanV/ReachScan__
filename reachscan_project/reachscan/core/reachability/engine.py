"""Package-aware reachability analysis.

For each vulnerability we locate its sink nodes in the call graph, then test
whether any entry point can reach a vulnerable sink. Reachable CVEs are
flagged for action; unreachable ones are suppressed.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from utils.logging import get_logger
from core.resolver.matching import match_score
from models.dependency import Vulnerability
from models.graph import CallGraph
from models.result import ReachabilityResult

log = get_logger(__name__)

# Confidence below this is treated as "no match" (mirrors v1 behaviour).
MATCH_THRESHOLD = 0.30
# Cap on how many execution paths are retained per vulnerability.
DEFAULT_MAX_PATHS = 3


class ReachabilityEngine:
    """Classifies vulnerabilities as reachable or unreachable."""

    def __init__(self, max_paths: int = DEFAULT_MAX_PATHS,
                 path_cutoff: int = 10):
        self.max_paths = max_paths
        self.path_cutoff = path_cutoff

    def analyze(self, vulnerability: Vulnerability,
                call_graph: CallGraph) -> ReachabilityResult:
        """Analyse a single vulnerability against a call graph."""
        G = call_graph.graph
        found_sinks, missing_sinks, confidence = self._find_sink_nodes(
            call_graph, vulnerability.vulnerable_functions, vulnerability.package
        )

        reachable_via: list[str] = []
        all_paths: list[list[str]] = []
        unreachable_sinks: list[str] = []

        for sink in found_sinks:
            sink_reachable = False

            for entry in call_graph.entry_points:
                if not G.has_node(entry):
                    continue

                try:
                    is_reachable = nx.has_path(G, source=entry, target=sink)
                except nx.NodeNotFound:
                    is_reachable = False

                if is_reachable:
                    sink_reachable = True
                    reachable_via.append(sink)
                    all_paths.extend(self._find_all_simple_paths(G, entry, sink))

            if not sink_reachable:
                unreachable_sinks.append(sink)

        unique_paths = self._dedupe_paths(all_paths)

        return ReachabilityResult(
            vulnerability=vulnerability,
            is_reachable=bool(reachable_via),
            reachable_via=list(set(reachable_via)),
            execution_paths=unique_paths,
            unreachable_sinks=unreachable_sinks,
            missing_sinks=missing_sinks,
            match_confidence=confidence,
        )

    def analyze_many(self, vulnerabilities: list[Vulnerability],
                     call_graph: CallGraph) -> list[ReachabilityResult]:
        """Analyse a batch of vulnerabilities against one call graph."""
        results = []
        for vuln in vulnerabilities:
            result = self.analyze(vuln, call_graph)
            results.append(result)
            log.debug(
                "%s (%s) [%s] -> %s (match %s)",
                vuln.cve_id, vuln.package, vuln.severity,
                result.status,
                f"{result.match_confidence:.0%}",
            )
        return results

    # -- helpers ----------------------------------------------------------

    def _find_sink_nodes(self, cg: CallGraph, vulnerable_functions: list[str],
                         package_name: str) -> tuple[list[str], list[str], float]:
        G = cg.graph
        found: list[str] = []
        missing: list[str] = []
        best_confidence = 0.0

        for vf in vulnerable_functions:
            best_match = None
            best_score = 0.0

            for node in G.nodes():
                score = match_score(node, vf, package_name)
                if score > best_score:
                    best_score = score
                    best_match = node

            if best_match and best_score >= MATCH_THRESHOLD:
                found.append(best_match)
                best_confidence = max(best_confidence, best_score)
            else:
                missing.append(vf)

        return list(set(found)), missing, best_confidence

    def _find_all_simple_paths(self, G: nx.DiGraph, source: str, sink: str) -> list[list[str]]:
        try:
            paths = list(nx.all_simple_paths(G, source=source, target=sink,
                                             cutoff=self.path_cutoff))
            return paths[: self.max_paths]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def _dedupe_paths(self, paths: list[list[str]]) -> list[list[str]]:
        seen: set = set()
        unique: list[list[str]] = []
        for p in paths:
            key = tuple(p)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique[: self.max_paths]