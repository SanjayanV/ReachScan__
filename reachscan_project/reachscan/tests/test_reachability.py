"""Tests for the reachability engine."""

import unittest

import networkx as nx

from core.reachability import ReachabilityEngine
from models import CallGraph, Vulnerability
from tests.helpers import make_vulnerability


def _graph(entry="main", path=("main", "mid", "demo.sink")):
    G = nx.DiGraph()
    for i in range(len(path) - 1):
        G.add_edge(path[i], path[i + 1])
    G.add_node("demo.isolated")
    return CallGraph(graph=G, entry_points=[entry], external_nodes=[],
                     internal_nodes=[], all_edges=list(G.edges()))


class ReachabilityTest(unittest.TestCase):
    def test_reachable_vulnerability(self):
        vuln = make_vulnerability(package="demo",
                                  vulnerable_functions=["demo.sink"])
        result = ReachabilityEngine().analyze(vuln, _graph())
        self.assertTrue(result.is_reachable)
        self.assertGreater(result.match_confidence, 0.0)
        self.assertTrue(result.execution_paths)

    def test_sink_isolated_is_unreachable(self):
        vuln = make_vulnerability(package="demo",
                                  vulnerable_functions=["demo.isolated"])
        result = ReachabilityEngine().analyze(vuln, _graph())
        self.assertFalse(result.is_reachable)
        self.assertIn("demo.isolated", result.unreachable_sinks)

    def test_missing_sink_reported(self):
        vuln = make_vulnerability(package="absent",
                                  vulnerable_functions=["absent.nope"])
        result = ReachabilityEngine().analyze(vuln, _graph())
        self.assertFalse(result.is_reachable)
        self.assertIn("absent.nope", result.missing_sinks)

    def test_analyze_many(self):
        results = ReachabilityEngine().analyze_many(
            [make_vulnerability("a"), make_vulnerability("b")], _graph()
        )
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()