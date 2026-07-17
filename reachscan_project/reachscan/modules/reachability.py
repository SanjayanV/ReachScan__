"""
Module 4: Reachability Traversal Engine
Uses DFS/BFS pathfinding to classify CVEs as Reachable or Unreachable
based on package-aware sink matching.
"""

import networkx as nx
from dataclasses import dataclass, field
from typing import Optional
from modules.graph import CallGraph
from modules.ingestion import Vulnerability


@dataclass
class ReachabilityResult:
    vulnerability: Vulnerability
    is_reachable: bool
    reachable_via: list[str]
    execution_paths: list[list[str]]
    unreachable_sinks: list[str]
    missing_sinks: list[str]
    match_confidence: float = 0.0

    @property
    def status(self) -> str:
        return "REACHABLE" if self.is_reachable else "UNREACHABLE"

    @property
    def priority(self) -> str:
        if not self.is_reachable:
            return "LOW"
        sev = self.vulnerability.severity
        if sev in ("CRITICAL", "HIGH"):
            return "CRITICAL"
        elif sev == "MEDIUM":
            return "HIGH"
        return "MEDIUM"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.vulnerability.cve_id,
            "package": self.vulnerability.package,
            "severity": self.vulnerability.severity,
            "priority": self.priority,
            "status": self.status,
            "is_reachable": self.is_reachable,
            "summary": self.vulnerability.summary,
            "vulnerable_functions": self.vulnerability.vulnerable_functions,
            "reachable_via": self.reachable_via,
            "execution_paths": self.execution_paths,
            "unreachable_sinks": self.unreachable_sinks,
            "missing_sinks": self.missing_sinks,
            "match_confidence": round(self.match_confidence, 2),
            "cvss_score": self.vulnerability.cvss_score,
            "fixed_version": self.vulnerability.fixed_version,
            "references": self.vulnerability.references,
        }


PACKAGE_TO_IMPORT = {
    "pyyaml":       ["yaml"],
    "pillow":       ["PIL", "Image"],
    "scikit-learn": ["sklearn"],
    "beautifulsoup4": ["bs4"],
    "python-dateutil": ["dateutil"],
    "opencv-python": ["cv2"],
    "pycryptodome": ["Crypto"],
}


def _get_import_names(package_name: str) -> list[str]:
    names = []
    pkg_lower = package_name.lower()
    if pkg_lower in PACKAGE_TO_IMPORT:
        names.extend(PACKAGE_TO_IMPORT[pkg_lower])

    names.extend([
        package_name,
        package_name.lower(),
        package_name.replace("-", "_"),
        package_name.replace("-", "_").lower(),
    ])

    return list(set(names))


def _match_score(node_name: str, vulnerable_func: str, package_name: str) -> float:
    node_lower = node_name.lower()
    vf_lower = vulnerable_func.lower()

    import_names = _get_import_names(package_name)
    import_names_lower = [n.lower() for n in import_names]

    if node_name == vulnerable_func:
        return 1.00

    if node_lower == vf_lower:
        return 0.95

    if node_lower.endswith("." + vf_lower):
        return 0.90

    vf_root = vf_lower.split(".")[0] if "." in vf_lower else ""
    node_root = node_lower.split(".")[0] if "." in node_lower else ""

    if vf_root:
        if node_root in import_names_lower or node_root == vf_root:
            vf_func = vf_lower.split(".")[-1]
            node_func = node_lower.split(".")[-1]
            if node_func == vf_func:
                return 0.80
        else:
            return 0.0

    if not vf_root:
        node_func = node_lower.split(".")[-1]
        if node_func == vf_lower:
            if node_root in import_names_lower:
                return 0.70
            if not node_root:
                return 0.30

    return 0.0


def _find_sink_nodes(cg: CallGraph, vulnerable_functions: list[str],
                     package_name: str) -> tuple[list[str], list[str], float]:
    G = cg.graph
    found = []
    missing = []
    best_confidence = 0.0

    for vf in vulnerable_functions:
        best_match = None
        best_score = 0.0

        for node in G.nodes():
            score = _match_score(node, vf, package_name)
            if score > best_score:
                best_score = score
                best_match = node

        if best_match and best_score >= 0.30:
            found.append(best_match)
            best_confidence = max(best_confidence, best_score)
        else:
            missing.append(vf)

    return list(set(found)), missing, best_confidence


def _find_all_simple_paths(G: nx.DiGraph, source: str, sink: str,
                           cutoff: int = 10) -> list[list[str]]:
    try:
        paths = list(nx.all_simple_paths(G, source=source, target=sink, cutoff=cutoff))
        return paths[:3]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def analyze_vulnerability(vuln: Vulnerability, cg: CallGraph,
                          max_paths: int = 3) -> ReachabilityResult:
    G = cg.graph

    found_sinks, missing_sinks, confidence = _find_sink_nodes(
        cg, vuln.vulnerable_functions, vuln.package
    )

    reachable_via = []
    all_paths = []
    unreachable_sinks = []

    for sink in found_sinks:
        sink_reachable = False

        for entry in cg.entry_points:
            if not G.has_node(entry):
                continue

            try:
                is_reachable = nx.has_path(G, source=entry, target=sink)
            except nx.NodeNotFound:
                is_reachable = False

            if is_reachable:
                sink_reachable = True
                reachable_via.append(sink)

                paths = _find_all_simple_paths(G, entry, sink)
                all_paths.extend(paths)

                seen = set()
                unique_paths = []
                for p in all_paths:
                    key = tuple(p)
                    if key not in seen:
                        seen.add(key)
                        unique_paths.append(p)
                all_paths = unique_paths[:max_paths]

        if not sink_reachable:
            unreachable_sinks.append(sink)

    return ReachabilityResult(
        vulnerability=vuln,
        is_reachable=bool(reachable_via),
        reachable_via=list(set(reachable_via)),
        execution_paths=all_paths,
        unreachable_sinks=unreachable_sinks,
        missing_sinks=missing_sinks,
        match_confidence=confidence,
    )


def run_reachability_analysis(vulnerabilities: list[Vulnerability],
                              cg: CallGraph,
                              verbose: bool = True) -> list[ReachabilityResult]:
    if verbose:
        print("\n╔══════════════════════════════════════════════╗")
        print("║   MODULE 4: Reachability Traversal Engine    ║")
        print("╚══════════════════════════════════════════════╝\n")

    if not vulnerabilities:
        if verbose:
            print("  [✓] No vulnerabilities to analyze.")
        return []

    results = []

    for vuln in vulnerabilities:
        result = analyze_vulnerability(vuln, cg)
        results.append(result)

        if verbose:
            icon = "🔴 REACHABLE  " if result.is_reachable else "✅ UNREACHABLE"
            conf = f" (match: {result.match_confidence:.0%})" if result.match_confidence > 0 else ""
            print(f"  {icon} │ {vuln.cve_id} ({vuln.package}) [{vuln.severity}]{conf}")

            if result.is_reachable and result.execution_paths:
                for path in result.execution_paths[:1]:
                    path_str = " → ".join([p.split(".")[-1] for p in path])
                    print(f"             └─ Path: {path_str}")
            elif not result.is_reachable:
                if result.unreachable_sinks:
                    sinks = ", ".join(s.split(".")[-1] for s in result.unreachable_sinks)
                    print(f"             └─ Sinks exist but unreachable: {sinks}")
                elif result.missing_sinks:
                    print(f"             └─ Vulnerable functions not found in codebase")

    reachable = [r for r in results if r.is_reachable]
    unreachable = [r for r in results if not r.is_reachable]

    if verbose:
        print(f"\n  ┌─────────────────────────────────────────┐")
        print(f"  │ TRIAGE SUMMARY                          │")
        print(f"  ├─────────────────────────────────────────┤")
        print(f"  │ Total CVEs Analyzed  : {len(results):<17}│")
        print(f"  │ 🔴 Reachable (Act)   : {len(reachable):<17}│")
        print(f"  │ ✅ Unreachable (Ign) : {len(unreachable):<17}│")
        if results:
            reduction = (len(unreachable) / len(results)) * 100
            print(f"  │ Alert Reduction      : {reduction:.0f}%{' ' * 14}│")
        print(f"  └─────────────────────────────────────────┘")

    return results
