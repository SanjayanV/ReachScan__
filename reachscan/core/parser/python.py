"""AST-based parser for Python source files.

The visitor walks each file, extracting function definitions, call edges and
imports. The analysis logic is unchanged from ReachScan v1; only the I/O
(printing -> logging) and structure have been refactored.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

from utils.logging import get_logger
from utils.exceptions import ParseError
from models.code import CallEdge, FunctionNode, ParsedModule
from core.parser.base import LanguageParser

log = get_logger(__name__)

# Default directories never descended into by the parser.
DEFAULT_SKIP_DIRS = frozenset(
    {
        "__pycache__", ".git", ".hg", ".svn",
        "venv", ".venv", "node_modules",
        ".tox", ".mypy_cache", ".pytest_cache",
        "dist", "build", "egg-info", ".eggs",
    }
)

ENTRY_POINT_NAMES = frozenset(
    {
        "main", "run", "start", "execute", "app", "handler",
        "lambda_handler", "entry", "process", "run_batch", "cli",
        "run_pipeline", "serve", "main_cli",
    }
)

ENTRY_POINT_DECORATORS = frozenset(
    {
        "app.route", "app.get", "app.post", "app.put", "app.delete",
        "router.route", "router.get", "router.post",
        "login_required", "require_auth",
        "celery.task", "shared_task",
        "click.command", "click.group",
    }
)

DUNDER_SKIP = frozenset(
    {
        "__init__", "__repr__", "__str__", "__eq__", "__hash__",
        "__len__", "__getitem__", "__setitem__", "__delitem__",
        "__contains__", "__iter__", "__next__",
    }
)

STDLIB_MODULES = frozenset(
    {
        "os", "sys", "re", "json", "math", "random", "time", "datetime",
        "pathlib", "collections", "itertools", "functools", "operator",
        "io", "logging", "argparse", "configparser", "hashlib", "hmac",
        "base64", "copy", "pprint", "textwrap", "string", "struct",
        "enum", "typing", "dataclasses", "abc", "contextlib",
        "threading", "multiprocessing", "concurrent", "asyncio",
        "socket", "http", "email", "html", "xml", "csv", "sqlite3",
        "unittest", "doctest", "tempfile", "shutil", "glob",
        "warnings", "traceback", "inspect", "dis", "builtins",
        "platform", "signal", "atexit", "weakref",
    }
)

PYTHON_BUILTINS = frozenset(
    {
        "print", "len", "range", "int", "float", "str", "bool", "list",
        "dict", "set", "tuple", "type", "isinstance", "issubclass",
        "hasattr", "getattr", "setattr", "delattr", "callable",
        "super", "property", "staticmethod", "classmethod",
        "open", "input", "abs", "max", "min", "sum", "sorted",
        "reversed", "enumerate", "zip", "map", "filter",
        "any", "all", "next", "iter", "repr", "hash", "id",
        "ValueError", "TypeError", "KeyError", "IndexError",
        "AttributeError", "RuntimeError", "StopIteration",
        "Exception", "FileNotFoundError", "IOError", "OSError",
        "NotImplementedError", "ImportError",
    }
)


class _FunctionCallVisitor(ast.NodeVisitor):
    """Extracts functions, call edges and module-global calls from one AST."""

    def __init__(self, file_path: str, module_name: str,
                 imports: dict, from_imports: dict):
        self.file_path = file_path
        self.module_name = module_name
        self.imports = imports
        self.from_imports = from_imports
        self.functions: list[FunctionNode] = []
        self.calls: list[CallEdge] = []
        self._current_function: str | None = None
        self._scope_stack: list[str] = []
        self._in_class: bool = False

    @staticmethod
    def _arg_reprs(node: ast.Call) -> list[str]:
        """Return a short textual representation of each positional argument."""
        reprs: list[str] = []
        for arg in node.args:
            try:
                reprs.append(ast.unparse(arg))
            except Exception:
                reprs.append("<expr>")
        return reprs

    def resolve_call(self, node: ast.Call) -> tuple[str, bool]:
        """Resolve a call AST node to a (name, is_external) pair."""
        func = node.func

        if isinstance(func, ast.Name):
            name = func.id
            if name in self.from_imports:
                module = self.from_imports[name]
                root_module = module.split(".")[0] if module else ""
                is_ext = root_module not in STDLIB_MODULES and root_module != self.module_name
                return f"{module}.{name}", is_ext
            if name in PYTHON_BUILTINS:
                return name, False
            return name, False

        if isinstance(func, ast.Attribute):
            parts: list[str] = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            dotted = ".".join(parts)

            root = parts[0] if parts else ""
            is_external = False

            if root in self.imports:
                real_module = self.imports[root]
                is_external = real_module not in STDLIB_MODULES
                if real_module != root:
                    dotted = real_module + "." + ".".join(parts[1:])
            elif root in self.from_imports:
                real_module = self.from_imports[root].split(".")[0]
                is_external = real_module not in STDLIB_MODULES and real_module != self.module_name

            return dotted, is_external

        return "<unknown>", False

    def _decorator_text(self, node) -> str:
        """Render a decorator node to its dotted string form."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts: list[str] = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return ".".join(parts)
        if isinstance(node, ast.Call):
            return self._decorator_text(node.func)
        return ""

    def _extract_decorators(self, node) -> list[str]:
        return [self._decorator_text(dec) for dec in node.decorator_list]

    def _is_entry_by_decorator(self, decorators: list[str]) -> bool:
        for dec in decorators:
            if dec in ENTRY_POINT_DECORATORS:
                return True
            for ep_dec in ENTRY_POINT_DECORATORS:
                if dec.endswith(ep_dec.split(".")[-1]) and "route" in dec:
                    return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._enter_function(node)

    def _enter_function(self, node):
        qualified = ".".join(self._scope_stack + [node.name])
        decorators = self._extract_decorators(node)

        is_entry = (
            node.name in ENTRY_POINT_NAMES or
            self._is_entry_by_decorator(decorators) or
            node.name == "main"
        )

        docstring = ""
        if (node.body and isinstance(node.body[0], ast.Expr) and
                isinstance(node.body[0].value, ast.Constant)):
            doc_val = node.body[0].value
            if isinstance(doc_val.value, str):
                docstring = doc_val.value[:200]

        fn = FunctionNode(
            name=node.name,
            qualified_name=qualified,
            file=self.file_path,
            line=node.lineno,
            is_entry_point=is_entry,
            is_method=self._in_class,
            decorators=decorators,
            docstring=docstring,
        )
        self.functions.append(fn)

        prev = self._current_function
        self._current_function = qualified
        self._scope_stack.append(node.name)

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                callee, is_ext = self.resolve_call(child)
                if callee and callee != "<unknown>" and callee not in PYTHON_BUILTINS:
                    fn.calls.append(callee)
                    self.calls.append(CallEdge(
                        caller=qualified,
                        callee=callee,
                        file=self.file_path,
                        line=getattr(child, "lineno", 0),
                        is_external=is_ext,
                        arg_reprs=self._arg_reprs(child),
                    ))

        self._scope_stack.pop()
        self._current_function = prev

    def visit_ClassDef(self, node: ast.ClassDef):
        self._scope_stack.append(node.name)
        prev_in_class = self._in_class
        self._in_class = True
        self.generic_visit(node)
        self._in_class = prev_in_class
        self._scope_stack.pop()


class AstPythonParser(LanguageParser):
    """Parses a directory of ``.py`` files into ``ParsedModule`` objects."""

    def __init__(self, skip_dirs: set[str] | frozenset[str] | None = None):
        self.skip_dirs = set(skip_dirs or DEFAULT_SKIP_DIRS)

    # -- interface -------------------------------------------------------

    def parse_file(self, file_path: str | Path) -> ParsedModule | None:
        return self._parse_file(Path(file_path))

    def parse_directory(self, directory: str | Path) -> list[ParsedModule]:
        py_files = self._discover_py_files(Path(directory))
        log.debug("Discovered %d Python source file(s)", len(py_files))

        parsed: list[ParsedModule] = []
        for fpath in py_files:
            mod = self._parse_file(fpath)
            if mod:
                parsed.append(mod)

        fn_count = sum(len(m.functions) for m in parsed)
        call_count = sum(len(m.calls) for m in parsed)
        log.info(
            "Parsed %d file(s): %d functions, %d call edge(s) (%d globally scoped)",
            len(parsed), fn_count, call_count,
            sum(len(m.global_calls) for m in parsed),
        )
        return parsed

    # -- helpers ---------------------------------------------------------

    def _discover_py_files(self, directory: Path) -> list[Path]:
        if not directory.exists():
            log.error("Target directory does not exist: %s", directory)
            return []

        py_files: list[Path] = []
        for root, dirs, files in os.walk(directory):
            dirs[:] = [
                d for d in dirs
                if d not in self.skip_dirs and not d.endswith(".egg-info")
            ]
            py_files.extend(
                Path(root) / f for f in files if f.endswith(".py")
            )
        return py_files

    def _parse_file(self, file_path: Path) -> ParsedModule | None:
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("Could not read %s: %s", file_path, exc)
            return None

        try:
            tree = ast.parse(source, filename=str(file_path))
        except SyntaxError as exc:
            log.warning("Syntax error in %s: %s", file_path, exc)
            return None

        module_name = file_path.stem
        imports, from_imports = self._extract_imports(tree)

        visitor = _FunctionCallVisitor(str(file_path), module_name, imports, from_imports)
        visitor.visit(tree)

        global_calls = self._extract_global_calls(tree, str(file_path), visitor)
        main_calls = self._extract_main_guard_calls(tree, str(file_path), visitor)

        return ParsedModule(
            file_path=str(file_path),
            module_name=module_name,
            imports=imports,
            from_imports=from_imports,
            functions=visitor.functions,
            calls=visitor.calls + main_calls,
            global_calls=global_calls,
        )

    def _extract_imports(self, tree: ast.Module) -> tuple[dict, dict]:
        imports: dict[str, str] = {}
        from_imports: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    key = alias.asname if alias.asname else alias.name.split(".")[0]
                    imports[key] = alias.name.split(".")[0]

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    key = alias.asname if alias.asname else alias.name
                    from_imports[key] = module

        return imports, from_imports

    def _extract_global_calls(self, tree: ast.Module, file_path: str,
                              visitor: _FunctionCallVisitor) -> list[CallEdge]:
        global_calls: list[CallEdge] = []

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee, is_ext = visitor.resolve_call(child)
                    if callee and callee != "<unknown>" and callee not in PYTHON_BUILTINS:
                        global_calls.append(CallEdge(
                            caller="<module_global>",
                            callee=callee,
                            file=file_path,
                            line=getattr(child, "lineno", 0),
                            is_external=is_ext,
                            arg_reprs=visitor._arg_reprs(child),
                        ))

        return global_calls

    def _extract_main_guard_calls(self, tree: ast.Module, file_path: str,
                                  visitor: _FunctionCallVisitor) -> list[CallEdge]:
        """Extract calls under ``if __name__ == "__main__":`` blocks."""
        main_calls: list[CallEdge] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            test = node.test
            if not (isinstance(test, ast.Compare) and
                    isinstance(test.left, ast.Name) and
                    test.left.id == "__name__"):
                continue

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee, is_ext = visitor.resolve_call(child)
                    if callee and callee not in PYTHON_BUILTINS:
                        main_calls.append(CallEdge(
                            caller="__main__",
                            callee=callee,
                            file=file_path,
                            line=getattr(child, "lineno", 0),
                            is_external=is_ext,
                            arg_reprs=visitor._arg_reprs(child),
                        ))

        return main_calls