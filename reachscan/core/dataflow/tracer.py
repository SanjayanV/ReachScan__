"""Intraprocedural / interprocedural dataflow tracer.

Given a call-graph path (list of qualified function names) already found by
``ReachabilityEngine``, this module determines whether the sink's dangerous
argument traces back to a taint source somewhere along that path.

This module does NOT walk the whole graph.  It only walks the specific path
handed to it, function by function.
"""

from __future__ import annotations

import ast
from pathlib import Path

from utils.logging import get_logger
from models.code import ParsedModule, CallEdge, FunctionNode
from models.dataflow import (
    DataflowResult,
    DataflowVerdict,
    TaintOrigin,
)
from core.dataflow.sources import classify_source, is_entry_point_function

log = get_logger(__name__)


class DataflowTracer:
    """Given a call-graph path already found by ReachabilityEngine, determines
    whether the sink's dangerous argument traces back to a taint source
    somewhere along that path.

    This does NOT walk the whole graph. It only walks the specific path
    handed to it, function by function, checking:
      1. Within the sink's own function body: is the argument passed to the
         sink call a Name that resolves (via local assignment or via being
         a parameter of this function) to something tainted?
      2. If the sink's function receives it as a parameter, walk back one
         call edge on the path: what expression did the caller pass for
         that parameter? Is THAT expression tainted (recurse) or a source
         signature match itself?
      3. Stop at path start (the entry point) — if we reach the entry
         point's own parameters without resolving, classify by whether
         the entry point param itself matches a source signature
         (FUNCTION_PARAM) → CONFIRMED, else UNCONFIRMED.
    """

    def trace(self, path: list[str], sink_call_arg_bindings: dict,
              parsed_modules: dict[str, ParsedModule]) -> DataflowResult:
        """Trace taint along *path* from an entry point toward a sink.

        Parameters
        ----------
        path:
            A list of qualified function names representing one
            ``all_simple_paths`` result, entry-point first, sink last.
        sink_call_arg_bindings:
            A mapping ``{callee_qualified_name: [arg_repr, ...]}`` for
            the last hop (the call from path[-2] → path[-1]).
        parsed_modules:
            The full set of parsed modules keyed by file path.
        """
        if len(path) < 2:
            return DataflowResult(
                verdict=DataflowVerdict.UNCONFIRMED,
                explanation="path too short to trace",
            )

        # Build lookup indices
        func_index = self._build_function_index(parsed_modules)
        edge_index = self._build_edge_index(parsed_modules)

        # Get the sink call's argument expressions
        sink_node_name = path[-1]
        caller_of_sink = path[-2]

        arg_reprs = self._get_arg_reprs_for_edge(
            edge_index, caller_of_sink, sink_node_name
        )

        if not arg_reprs:
            # The direct sink call has no positional args (e.g. Environment()).
            # Strategy: check if the caller_of_sink (the function containing
            # the sink call) receives any tainted params from further up the
            # path.  If it does, the data flows into the function's scope
            # where the sink is called.
            if len(path) >= 3:
                result = self._trace_function_params_from_caller(
                    caller_of_sink, path, func_index, edge_index,
                    parsed_modules,
                )
                if result:
                    return result

            return DataflowResult(
                verdict=DataflowVerdict.UNCONFIRMED,
                explanation="no argument info captured for sink call",
            )

        # Check if ALL arguments are literals → NOT_APPLICABLE
        all_literal = all(self._is_literal_repr(a) for a in arg_reprs)
        if all_literal:
            return DataflowResult(
                verdict=DataflowVerdict.NOT_APPLICABLE,
                explanation="all sink arguments are literal constants",
            )

        # For each non-literal argument, try to trace it back
        for arg_expr in arg_reprs:
            if self._is_literal_repr(arg_expr):
                continue

            result = self._trace_arg_back(
                arg_expr, caller_of_sink, path, func_index,
                edge_index, parsed_modules,
            )
            if result and result.verdict == DataflowVerdict.CONFIRMED:
                return result

        # Could not confirm any argument as tainted
        return DataflowResult(
            verdict=DataflowVerdict.UNCONFIRMED,
            explanation="could not trace sink arguments to a known taint source",
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _trace_function_params_from_caller(
        self,
        func_name: str,
        path: list[str],
        func_index: dict[str, FunctionNode],
        edge_index: dict[tuple[str, str], list[CallEdge]],
        parsed_modules: dict[str, ParsedModule],
    ) -> DataflowResult | None:
        """When a sink call has no args, check whether the containing function
        receives any tainted parameters from its caller in the path."""
        fn_node = func_index.get(func_name)
        if not fn_node:
            return None

        params = self._get_function_params(fn_node, parsed_modules)
        if not params:
            return None

        # Find the caller in the path
        func_idx = None
        for i, node_name in enumerate(path):
            if node_name == func_name:
                func_idx = i
                break

        if func_idx is None or func_idx == 0:
            return None

        caller = path[func_idx - 1]
        caller_arg_reprs = self._get_arg_reprs_for_edge(
            edge_index, caller, func_name,
        )

        for param_idx, param_name in enumerate(params):
            if caller_arg_reprs and param_idx < len(caller_arg_reprs):
                caller_arg = caller_arg_reprs[param_idx]
                if self._is_literal_repr(caller_arg):
                    continue

                result = self._trace_arg_back(
                    caller_arg, caller, path, func_index,
                    edge_index, parsed_modules,
                )
                if result and result.verdict == DataflowVerdict.CONFIRMED:
                    return result

        return None

    def _trace_arg_back(
        self,
        arg_expr: str,
        current_func: str,
        path: list[str],
        func_index: dict[str, FunctionNode],
        edge_index: dict[tuple[str, str], list[CallEdge]],
        parsed_modules: dict[str, ParsedModule],
        depth: int = 0,
    ) -> DataflowResult | None:
        """Recursively trace *arg_expr* backwards along *path*."""
        if depth > 20:
            return None

        # Check if the expression itself matches a source signature
        source_origin = classify_source(arg_expr)
        if source_origin is not None:
            return DataflowResult(
                verdict=DataflowVerdict.CONFIRMED,
                tainted_path_segment=[current_func],
                origin=source_origin,
                explanation=f"argument '{arg_expr}' matches source pattern ({source_origin.value})",
            )

        # If arg_expr is a simple name, check if it's a parameter of current_func
        fn_node = func_index.get(current_func)
        if fn_node:
            params = self._get_function_params(fn_node, parsed_modules)
            if arg_expr in params:
                # It's a parameter — walk back one step on the path
                current_idx = None
                for i, node_name in enumerate(path):
                    if node_name == current_func:
                        current_idx = i
                        break

                if current_idx is not None and current_idx > 0:
                    caller = path[current_idx - 1]
                    # Find what the caller passed for this parameter
                    caller_arg_reprs = self._get_arg_reprs_for_edge(
                        edge_index, caller, current_func,
                    )
                    param_idx = params.index(arg_expr)
                    if caller_arg_reprs and param_idx < len(caller_arg_reprs):
                        caller_arg = caller_arg_reprs[param_idx]
                        if self._is_literal_repr(caller_arg):
                            return None  # traced to literal, not tainted

                        return self._trace_arg_back(
                            caller_arg, caller, path, func_index,
                            edge_index, parsed_modules, depth + 1,
                        )

                # Reached the start of the path (entry point)
                if current_idx == 0:
                    if is_entry_point_function(
                        fn_node.name,
                        fn_node.decorators,
                    ):
                        return DataflowResult(
                            verdict=DataflowVerdict.CONFIRMED,
                            tainted_path_segment=[current_func],
                            origin=TaintOrigin.FUNCTION_PARAM,
                            explanation=f"parameter '{arg_expr}' of entry point '{current_func}'",
                        )
                    return None

            # Not a parameter — try to resolve via local assignment
            origin = self._resolve_local_assignment(
                arg_expr, current_func, fn_node, parsed_modules,
                path, func_index, edge_index, depth,
            )
            if origin is not None:
                return origin

        # Expression is too complex (subscript, attribute chain, etc.)
        # Per spec: prefer UNCONFIRMED over guessing CONFIRMED
        return None

    def _resolve_local_assignment(
        self,
        var_name: str,
        func_qualified: str,
        fn_node: FunctionNode,
        parsed_modules: dict[str, ParsedModule],
        path: list[str],
        func_index: dict[str, FunctionNode],
        edge_index: dict[tuple[str, str], list[CallEdge]],
        depth: int,
    ) -> DataflowResult | None:
        """Try to find where *var_name* was assigned in *func_qualified*'s body."""
        # Re-parse the function's file to get the AST
        func_ast = self._get_function_ast(fn_node, parsed_modules)
        if func_ast is None:
            return None

        # Walk assignments in the function body
        for node in ast.walk(func_ast):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        # Found the assignment — check the value
                        try:
                            rhs_repr = ast.unparse(node.value)
                        except Exception:
                            continue

                        source_origin = classify_source(rhs_repr)
                        if source_origin is not None:
                            return DataflowResult(
                                verdict=DataflowVerdict.CONFIRMED,
                                tainted_path_segment=[func_qualified],
                                origin=source_origin,
                                explanation=f"'{var_name}' assigned from '{rhs_repr}' ({source_origin.value})",
                            )

                        if self._is_literal_repr(rhs_repr):
                            return None  # assigned from a literal

                        # Recurse on the RHS expression
                        result = self._trace_arg_back(
                            rhs_repr, func_qualified, path, func_index,
                            edge_index, parsed_modules, depth + 1,
                        )
                        if result:
                            return result

            # Also check augmented assignments like +=
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name) and node.target.id == var_name:
                    return None  # too complex to trace

        return None

    def _get_function_ast(
        self,
        fn_node: FunctionNode,
        parsed_modules: dict[str, ParsedModule],
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Return the AST node for a function, re-parsing lazily if needed."""
        file_path = fn_node.file
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=file_path)
        except (OSError, SyntaxError):
            return None

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == fn_node.name and node.lineno == fn_node.line:
                    return node

        return None

    def _get_function_params(
        self,
        fn_node: FunctionNode,
        parsed_modules: dict[str, ParsedModule],
    ) -> list[str]:
        """Return the parameter names of a function."""
        func_ast = self._get_function_ast(fn_node, parsed_modules)
        if func_ast is None:
            return []

        params: list[str] = []
        for arg in func_ast.args.args:
            if arg.arg != "self" and arg.arg != "cls":
                params.append(arg.arg)
        return params

    @staticmethod
    def _build_function_index(
        parsed_modules: dict[str, ParsedModule],
    ) -> dict[str, FunctionNode]:
        """Map qualified function name → FunctionNode."""
        index: dict[str, FunctionNode] = {}
        for mod in parsed_modules.values():
            for fn in mod.functions:
                index[fn.qualified_name] = fn
                # Also index by short name for fallback
                index[fn.name] = fn
        return index

    @staticmethod
    def _build_edge_index(
        parsed_modules: dict[str, ParsedModule],
    ) -> dict[tuple[str, str], list[CallEdge]]:
        """Map (caller, callee) → list of CallEdge."""
        index: dict[tuple[str, str], list[CallEdge]] = {}
        for mod in parsed_modules.values():
            for edge in mod.calls:
                key = (edge.caller, edge.callee)
                index.setdefault(key, []).append(edge)
            for edge in mod.global_calls:
                key = (edge.caller, edge.callee)
                index.setdefault(key, []).append(edge)
        return index

    @staticmethod
    def _get_arg_reprs_for_edge(
        edge_index: dict[tuple[str, str], list[CallEdge]],
        caller: str,
        callee: str,
    ) -> list[str]:
        """Return the arg_reprs for the first matching edge."""
        # Direct match
        edges = edge_index.get((caller, callee), [])
        if edges and edges[0].arg_reprs:
            return edges[0].arg_reprs

        # Try short-name matching (callee might be stored differently in the
        # edge index due to module-prefixed names vs graph-resolved names)
        callee_short = callee.split(".")[-1]
        caller_short = caller.split(".")[-1] if "." in caller else caller
        for (c_from, c_to), edge_list in edge_index.items():
            if not edge_list or not edge_list[0].arg_reprs:
                continue
            c_from_short = c_from.split(".")[-1] if "." in c_from else c_from
            c_to_short = c_to.split(".")[-1] if "." in c_to else c_to
            if (c_from_short == caller_short or c_from == caller) and \
               (c_to_short == callee_short or c_to == callee):
                return edge_list[0].arg_reprs

        return []

    @staticmethod
    def _is_literal_repr(expr: str) -> bool:
        """Return True if the expression looks like a literal constant."""
        stripped = expr.strip()
        if not stripped:
            return False

        # String literals
        if (stripped.startswith("'") and stripped.endswith("'")) or \
           (stripped.startswith('"') and stripped.endswith('"')):
            return True

        # Numeric literals
        try:
            float(stripped)
            return True
        except ValueError:
            pass

        # None, True, False
        if stripped in ("None", "True", "False"):
            return True

        # All-caps identifiers (module-level constants like CONFIG_FILE)
        if stripped.replace("_", "").isalpha() and stripped == stripped.upper() and len(stripped) > 1:
            return True

        return False
