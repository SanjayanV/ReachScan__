"""Constructs a NetworkX DiGraph representing inter-function calls."""

from __future__ import annotations

import networkx as nx

from utils.logging import get_logger
from models.code import ParsedModule
from models.graph import CallGraph, GraphStats

log = get_logger(__name__)


def _is_noise_node(name: str) -> bool:
    """True for stdlib/builtin/invalid nodes that should be pruned."""
    from core.parser.python import PYTHON_BUILTINS, STDLIB_MODULES
    if name in PYTHON_BUILTINS:
        return True
    root = name.split(".")[0] if "." in name else ""
    if root in STDLIB_MODULES:
        return True
    if name.startswith("<") or name in ("", "<unknown>"):
        return True
    return False


class GraphBuilder:
    """Builds a graph of nodes=functions, edges=calls from parsed modules."""

    def build(self, parsed_modules: list[ParsedModule]) -> CallGraph:
        log.debug("Building call graph from %d module(s)", len(parsed_modules))

        G = nx.DiGraph()
        module_function_index: dict[str, str] = {}
        internal_nodes: list[str] = []
        entry_points: list[str] = []

        for mod in parsed_modules:
            for fn in mod.functions:
                label = fn.qualified_name.strip()
                node_type = "entry" if fn.is_entry_point else "internal"

                G.add_node(
                    label,
                    type=node_type,
                    file=fn.file,
                    line=fn.line,
                    module=mod.module_name,
                    display_name=fn.name,
                    decorators=fn.decorators,
                    docstring=fn.docstring,
                    is_method=fn.is_method,
                )

                internal_nodes.append(label)
                if fn.is_entry_point:
                    entry_points.append(label)

                module_function_index[fn.name] = label
                module_function_index[f"{mod.module_name}.{fn.name}"] = label

        if not G.has_node("__main__"):
            G.add_node("__main__", type="entry", file="", line=0,
                       display_name="__main__", module="", decorators=[])
            entry_points.append("__main__")

        external_nodes: list[str] = []
        external_set: set[str] = set()

        for mod in parsed_modules:
            for edge in mod.calls:
                caller = edge.caller.strip()
                callee = edge.callee.strip()

                if _is_noise_node(callee):
                    continue

                if not G.has_node(caller):
                    G.add_node(caller, type="internal", file=edge.file, line=0,
                               display_name=caller.split(".")[-1],
                               module=mod.module_name, decorators=[])
                    internal_nodes.append(caller)

                if edge.is_external:
                    if not G.has_node(callee):
                        G.add_node(callee, type="external", file="", line=0,
                                   display_name=callee, module="", decorators=[])
                        if callee not in external_set:
                            external_nodes.append(callee)
                            external_set.add(callee)
                else:
                    callee = self._resolve_internal(callee, internal_nodes, G,
                                                    module_function_index)

                if not G.has_edge(caller, callee):
                    G.add_edge(caller, callee, file=edge.file, line=edge.line)

        # Promote external nodes that actually resolve to an internal function.
        for ext_node in list(external_nodes):
            short = ext_node.split(".")[-1]
            if short in module_function_index:
                internal = module_function_index[short]
                if internal != ext_node and G.has_node(ext_node) and G.has_node(internal):
                    for pred in list(G.predecessors(ext_node)):
                        edge_data = G.edges[pred, ext_node]
                        if not G.has_edge(pred, internal):
                            G.add_edge(pred, internal,
                                       file=edge_data.get("file", ""),
                                       line=edge_data.get("line", 0))
                    G.remove_node(ext_node)
                    external_nodes.remove(ext_node)
                    external_set.discard(ext_node)

        log.info(
            "Call graph built: %d nodes, %d edges (%d internal, %d external)",
            G.number_of_nodes(), G.number_of_edges(),
            len(internal_nodes), len(external_nodes),
        )

        return CallGraph(
            graph=G,
            entry_points=entry_points,
            external_nodes=external_nodes,
            internal_nodes=internal_nodes,
            all_edges=list(G.edges()),
            stats=compute_stats(G, internal_nodes, external_nodes, entry_points),
        )

    @staticmethod
    def _resolve_internal(callee: str, known_nodes: list[str],
                          G: nx.DiGraph, index: dict[str, str]) -> str:
        """Resolve a callee name to a real graph node when possible."""
        if G.has_node(callee):
            return callee

        if callee in index:
            target = index[callee]
            if G.has_node(target):
                return target

        short = callee.split(".")[-1]
        if short in index:
            target = index[short]
            if G.has_node(target):
                return target

        for node in known_nodes:
            if node == callee or node.endswith("." + callee):
                return node

        if not G.has_node(callee) and not _is_noise_node(callee):
            G.add_node(callee, type="unresolved", file="", line=0,
                       display_name=callee.split(".")[-1], module="", decorators=[])

        return callee


def get_reachable_nodes(cg: CallGraph) -> set[str]:
    """Nodes reachable from any entry point (used as an optimisation hint)."""
    reachable: set[str] = set()
    for ep in cg.entry_points:
        if cg.graph.has_node(ep):
            reachable |= nx.descendants(cg.graph, ep)
            reachable.add(ep)
    return reachable


def compute_stats(G: nx.DiGraph, internal: list, external: list,
                  entries: list) -> GraphStats:
    stats = GraphStats()
    stats.total_nodes = G.number_of_nodes()
    stats.internal_nodes = len(internal)
    stats.external_nodes = len(external)
    stats.entry_points = len(entries)
    stats.total_edges = G.number_of_edges()

    stats.unresolved_nodes = sum(
        1 for n in G.nodes() if G.nodes[n].get("type") == "unresolved"
    )

    if G.number_of_nodes() > 0:
        out_degrees = [d for _, d in G.out_degree()]
        stats.avg_out_degree = (sum(out_degrees) / len(out_degrees)) if out_degrees else 0
        stats.max_out_degree = max(out_degrees) if out_degrees else 0
        stats.max_out_degree_node = max(G.nodes(), key=lambda n: G.out_degree(n))

    undirected = G.to_undirected()
    stats.connected_components = nx.number_connected_components(undirected)
    stats.isolated_nodes = sum(1 for n in G.nodes() if G.degree(n) == 0)
    stats.graph_density = nx.density(G) if G.number_of_nodes() > 1 else 0.0

    return stats