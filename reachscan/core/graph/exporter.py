"""Export helpers that turn a call graph into serialisable formats."""

from __future__ import annotations

from models.graph import CallGraph


def export_graph_summary(cg: CallGraph) -> dict:
    """Produce a JSON-serialisable summary of the call graph."""
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
        "edges": [{"from": u, "to": v} for u, v in G.edges()],
    }


def export_dot(cg: CallGraph) -> str:
    """Render the call graph as a Graphviz DOT string."""
    G = cg.graph
    lines = ["digraph ReachScan {"]
    lines.append('  rankdir=LR;')
    lines.append('  node [fontname="Helvetica", fontsize=10];')
    lines.append('  edge [color="#666666"];')
    lines.append("")

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