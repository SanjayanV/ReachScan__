"""Models describing the constructed call graph."""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx


@dataclass
class GraphStats:
    """Aggregate metrics computed from a call graph."""

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
    """A wrapper around a NetworkX DiGraph plus cached lookups."""

    graph: nx.DiGraph
    entry_points: list[str]
    external_nodes: list[str]
    internal_nodes: list[str]
    all_edges: list[tuple[str, str]]
    stats: GraphStats = field(default_factory=GraphStats)