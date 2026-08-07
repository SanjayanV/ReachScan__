"""Models produced by the AST source-code parser."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FunctionNode:
    """A function (or method) found during AST traversal."""

    name: str
    qualified_name: str
    file: str
    line: int
    is_entry_point: bool = False
    is_method: bool = False
    decorators: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    docstring: str = ""


@dataclass
class CallEdge:
    """A directed caller -> callee relationship."""

    caller: str
    callee: str
    file: str
    line: int
    is_external: bool = False


@dataclass
class ParsedModule:
    """Result of parsing a single source file."""

    file_path: str
    module_name: str
    imports: dict[str, str]
    from_imports: dict[str, str]
    functions: list[FunctionNode]
    calls: list[CallEdge]
    global_calls: list[CallEdge] = field(default_factory=list)