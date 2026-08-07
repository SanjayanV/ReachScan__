"""Tests for call-graph construction."""

import unittest

import networkx as nx

from core.graph import GraphBuilder
from core.graph.builder import get_reachable_nodes
from models import CallGraph, CallEdge, FunctionNode, ParsedModule
from tests.helpers import TempProject


class GraphBuilderTest(unittest.TestCase):
    def _module(self, file_path="app.py", module_name="app"):
        return ParsedModule(
            file_path=file_path,
            module_name=module_name,
            imports={"yaml": "yaml", "requests": "requests"},
            from_imports={},
            functions=[
                FunctionNode("run", "app.run", file_path, 1, is_entry_point=True),
                FunctionNode("parse", "app.parse", file_path, 5),
            ],
            calls=[
                CallEdge("app.run", "app.parse", file_path, 2),
                CallEdge("app.parse", "yaml.safe_load", file_path, 6, is_external=True),
                CallEdge("app.parse", "print", file_path, 7),
            ],
        )

    def test_builds_graph_with_noise_removed(self):
        mod = self._module()
        cg = GraphBuilder().build([mod])
        self.assertIn("app.run", cg.graph.nodes)
        self.assertIn("yaml.safe_load", cg.graph.nodes)
        # stdlib/builtin call removed
        self.assertNotIn("print", cg.graph.nodes)

    def test_entry_points_registered(self):
        cg = GraphBuilder().build([self._module()])
        self.assertIn("app.run", cg.entry_points)

    def test_external_sinks_tagged(self):
        cg = GraphBuilder().build([self._module()])
        self.assertEqual(cg.graph.nodes["yaml.safe_load"]["type"], "external")

    def test_reachable_nodes(self):
        cg = GraphBuilder().build([self._module()])
        reachable = get_reachable_nodes(cg)
        self.assertIn("app.run", reachable)
        self.assertIn("yaml.safe_load", reachable)

    def test_export_dot_has_edges(self):
        cg = GraphBuilder().build([self._module()])
        from core.graph.exporter import export_dot
        self.assertIn("->", export_dot(cg))

    def test_unresolved_node_creation(self):
        mod = self._module()
        mod.calls.append(CallEdge("app.run", "mystery_func", mod.file_path, 9))
        cg = GraphBuilder().build([mod])
        self.assertEqual(cg.graph.nodes["mystery_func"]["type"], "unresolved")


if __name__ == "__main__":
    unittest.main()