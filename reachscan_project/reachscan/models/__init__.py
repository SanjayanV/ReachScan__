"""Data models shared across ReachScan modules."""

from models.dependency import Dependency, Vulnerability
from models.code import CallEdge, FunctionNode, ParsedModule
from models.graph import CallGraph, GraphStats
from models.result import ReachabilityResult

__all__ = [
    "Dependency", "Vulnerability",
    "CallEdge", "FunctionNode", "ParsedModule",
    "CallGraph", "GraphStats",
    "ReachabilityResult",
]