"""
Module 3: Call Graph Construction
Builds a NetworkX DiGraph from parsed AST data.
"""

import networkx as nx
from dataclasses import dataclass, field
from typing import Any
from modules.parser import ParsedModule, FunctionNode, CallEdge, STDLIB_MODULES, PYTHON_BUILTINS


@dataclass
class GraphStats:
    total_nodes: int = 0
    internal_nodes: int = 0
    external_nodes: int = 0
    entry_points: int = 0
    unresolved_nodes: int = 0
    total_edges: int = 0
    avg_out_degree: float = 0.0
    max_out_degree: int = 0
    max_out_degree_node: str = ""
    connected_components: int = 0
    isolated_nodes: int = 0
    graph_density: float = 0.0


@dataclass
class CallGraph:
    graph: nx.DiGraph
    entry_points: list[str]
    external_nodes: list[str]
    internal_nodes: list[str]
    all_edges: list[tuple[str, str]]
    stats: GraphStats = field(default_factory=GraphStats)


def _node_label(name: str) -> str:
    return name.strip()


def _is_noise_node(name: str) -> bool:
    if name in PYTHON_BUILTINS:
        return True
    root = name.split(".")[0] if "." in name else ""
    if root in STDLIB_MODULES:
        return True
    if name.startswith("<") or name in ("", "<unknown>"):
        return True
    return False


def build_call_graph(parsed_modules: list[ParsedModule],
                     verbose: bool = True) -> CallGraph:
    if verbose:
        print("\n╔══════════════════════════════════════════════╗")
        print("║     MODULE 3: Call Graph Construction        ║")
        print("╚══════════════════════════════════════════════╝\n")

    G = nx.DiGraph()

    module_function_index: dict[str, str] = {}

    internal_nodes: list[str] = []
    entry_points: list[str] = []

    for mod in parsed_modules:
        for fn in mod.functions:
            label = _node_label(fn.qualified_name)
            node_type = "entry" if fn.is_entry_point else "internal"

            G.add_node(label,
                       type=node_type,
                       file=fn.file,
                       line=fn.line,
                       module=mod.module_name,
                       display_name=fn.name,
                       decorators=fn.decorators,
                       docstring=fn.docstring,
                       is_method=fn.is_method)

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
            caller = _node_label(edge.caller)
            callee = _node_label(edge.callee)

            if _is_noise_node(callee):
                continue

            if not G.has_node(caller):
                G.add_node(caller, type="internal", file=edge.file, line=0,
                           display_name=caller.split(".")[-1], module=mod.module_name,
                           decorators=[])
                internal_nodes.append(caller)

            if edge.is_external:
                if not G.has_node(callee):
                    G.add_node(callee, type="external", file="", line=0,
                               display_name=callee, module="", decorators=[])
                    if callee not in external_set:
                        external_nodes.append(callee)
                        external_set.add(callee)
            else:
                resolved = _resolve_internal(callee, internal_nodes, G,
                                             module_function_index)
                callee = resolved

            if not G.has_edge(caller, callee):
                G.add_edge(caller, callee, file=edge.file, line=edge.line)

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

    all_edges = list(G.edges())
    stats = _compute_stats(G, internal_nodes, external_nodes, entry_points)

    if verbose:
        print(f"  [✓] Call graph built successfully.")
        print(f"      Total nodes      : {G.number_of_nodes()}")
        print(f"      Internal nodes   : {len(internal_nodes)}")
        print(f"      External sinks   : {len(external_nodes)}")
        print(f"      Entry points     : {entry_points}")
        print(f"      Total edges      : {G.number_of_edges()}")
        print(f"      Graph density    : {stats.graph_density:.4f}")
        print(f"      Isolated nodes   : {stats.isolated_nodes}")
        if stats.max_out_degree_node:
            print(f"      Highest fan-out  : {stats.max_out_degree_node} "
                  f"({stats.max_out_degree} calls)")

        if G.number_of_nodes() <= 60:
            print(f"\n  [*] Graph adjacency preview (first 20 edges):")
            for i, (u, v) in enumerate(all_edges[:20]):
                v_type = G.nodes[v].get("type", "?")
                marker = "🔴" if v_type == "external" else "→"
                print(f"      {u} {marker} {v}")
            if len(all_edges) > 20:
                print(f"      ... ({len(all_edges) - 20} more edges)")

    return CallGraph(
        graph=G, entry_points=entry_points, external_nodes=external_nodes,
        internal_nodes=internal_nodes, all_edges=all_edges, stats=stats,
    )


def _resolve_internal(callee: str, known_nodes: list[str],
                      G: nx.DiGraph, index: dict[str, str]) -> str:
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


def _compute_stats(G: nx.DiGraph, internal: list, external: list,
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
        stats.avg_out_degree = sum(out_degrees) / len(out_degrees) if out_degrees else 0
        stats.max_out_degree = max(out_degrees) if out_degrees else 0
        max_node = max(G.nodes(), key=lambda n: G.out_degree(n))
        stats.max_out_degree_node = max_node

    undirected = G.to_undirected()
    stats.connected_components = nx.number_connected_components(undirected)
    stats.isolated_nodes = sum(1 for n in G.nodes() if G.degree(n) == 0)
    stats.graph_density = nx.density(G) if G.number_of_nodes() > 1 else 0.0

    return stats


def get_reachable_nodes(cg: CallGraph) -> set[str]:
    reachable = set()
    for ep in cg.entry_points:
        if cg.graph.has_node(ep):
            reachable |= nx.descendants(cg.graph, ep)
            reachable.add(ep)
    return reachable


def export_graph_summary(cg: CallGraph) -> dict:
    G = cg.graph
    return {
        "node_count": G.number_of_nodes(),
        "edge_count": G.number_of_edges(),
        "entry_points": cg.entry_points,
        "external_sinks": cg.external_nodes,
        "stats": {
            "density": round(cg.stats.graph_density, 4),
            "connected_components": cg.stats.connected_components,
            "isolated_nodes": cg.stats.isolated_nodes,
            "max_fan_out": cg.stats.max_out_degree,
            "max_fan_out_node": cg.stats.max_out_degree_node,
        },
        "nodes": [
            {"id": n, "type": G.nodes[n].get("type", "unknown"),
             "file": G.nodes[n].get("file", ""), "line": G.nodes[n].get("line", 0)}
            for n in G.nodes()
        ],
        "edges": [{"from": u, "to": v} for u, v in G.edges()]
    }


def export_dot(cg: CallGraph) -> str:
    lines = ["digraph ReachScan {"]
    lines.append('  rankdir=LR;')
    lines.append('  node [fontname="Helvetica", fontsize=10];')
    lines.append('  edge [color="#666666"];')
    lines.append("")

    G = cg.graph
    for n in G.nodes():
        ntype = G.nodes[n].get("type", "unknown")
        display = G.nodes[n].get("display_name", n)
        if ntype == "entry":
            lines.append(f'  "{n}" [label="{display}", shape=diamond, '
                         f'style=filled, fillcolor="#4f8ef7", fontcolor=white];')
        elif ntype == "external":
            lines.append(f'  "{n}" [label="{display}", shape=box, '
                         f'style=filled, fillcolor="#ff4757", fontcolor=white];')
        elif ntype == "internal":
            lines.append(f'  "{n}" [label="{display}", shape=ellipse, '
                         f'style=filled, fillcolor="#f0f0f0"];')
        else:
            lines.append(f'  "{n}" [label="{display}", shape=ellipse, '
                         f'style=dashed, color="#999999"];')

    lines.append("")
    for u, v in G.edges():
        lines.append(f'  "{u}" -> "{v}";')

    lines.append("}")
    return "\n".join(lines)
