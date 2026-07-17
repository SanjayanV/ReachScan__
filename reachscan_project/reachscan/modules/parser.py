"""
Module 2: Code Parsing Engine (AST)
Parses Python source files and extracts function definitions, calls, and imports.
"""

import ast
import os
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionNode:
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
    caller: str
    callee: str
    file: str
    line: int
    is_external: bool = False


@dataclass
class ParsedModule:
    file_path: str
    module_name: str
    imports: dict[str, str]
    from_imports: dict[str, str]
    functions: list[FunctionNode]
    calls: list[CallEdge]
    global_calls: list[CallEdge] = field(default_factory=list)


ENTRY_POINT_NAMES = {
    "main", "run", "start", "execute", "app", "handler",
    "lambda_handler", "entry", "process", "run_batch", "cli",
    "run_pipeline", "serve", "main_cli",
}

ENTRY_POINT_DECORATORS = {
    "app.route", "app.get", "app.post", "app.put", "app.delete",
    "router.route", "router.get", "router.post",
    "login_required", "require_auth",
    "celery.task", "shared_task",
    "click.command", "click.group",
}

DUNDER_SKIP = {"__init__", "__repr__", "__str__", "__eq__", "__hash__",
               "__len__", "__getitem__", "__setitem__", "__delitem__",
               "__contains__", "__iter__", "__next__"}

STDLIB_MODULES = {
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

PYTHON_BUILTINS = {
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


class FunctionCallVisitor(ast.NodeVisitor):

    def __init__(self, file_path: str, module_name: str,
                 imports: dict, from_imports: dict):
        self.file_path = file_path
        self.module_name = module_name
        self.imports = imports
        self.from_imports = from_imports
        self.functions: list[FunctionNode] = []
        self.calls: list[CallEdge] = []
        self.global_calls: list[CallEdge] = []
        self._current_function: Optional[str] = None
        self._scope_stack: list[str] = []
        self._in_class: bool = False

    def _resolve_call(self, node: ast.Call) -> tuple[str, bool]:
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

        elif isinstance(func, ast.Attribute):
            parts = []
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

    def _extract_decorators(self, node) -> list[str]:
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                parts = []
                current = dec
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                parts.reverse()
                decorators.append(".".join(parts))
            elif isinstance(dec, ast.Call):
                dec_func = dec.func
                if isinstance(dec_func, ast.Name):
                    decorators.append(dec_func.id)
                elif isinstance(dec_func, ast.Attribute):
                    parts = []
                    current = dec_func
                    while isinstance(current, ast.Attribute):
                        parts.append(current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        parts.append(current.id)
                    parts.reverse()
                    decorators.append(".".join(parts))
        return decorators

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
                callee, is_ext = self._resolve_call(child)
                if callee and callee != "<unknown>" and callee not in PYTHON_BUILTINS:
                    fn.calls.append(callee)
                    self.calls.append(CallEdge(
                        caller=qualified,
                        callee=callee,
                        file=self.file_path,
                        line=getattr(child, "lineno", 0),
                        is_external=is_ext,
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


def extract_imports(tree: ast.Module) -> tuple[dict, dict]:
    imports = {}
    from_imports = {}

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


def extract_global_calls(tree: ast.Module, file_path: str,
                         imports: dict, from_imports: dict,
                         visitor: FunctionCallVisitor) -> list[CallEdge]:
    global_calls = []

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                callee, is_ext = visitor._resolve_call(child)
                if callee and callee != "<unknown>" and callee not in PYTHON_BUILTINS:
                    global_calls.append(CallEdge(
                        caller="<module_global>",
                        callee=callee,
                        file=file_path,
                        line=getattr(child, "lineno", 0),
                        is_external=is_ext,
                    ))

    return global_calls


def parse_file(file_path: str) -> Optional[ParsedModule]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        print(f"  [!] Could not read {file_path}: {e}")
        return None

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        print(f"  [!] Syntax error in {file_path}: {e}")
        return None

    module_name = Path(file_path).stem
    imports, from_imports = extract_imports(tree)

    visitor = FunctionCallVisitor(file_path, module_name, imports, from_imports)
    visitor.visit(tree)

    global_calls = extract_global_calls(tree, file_path, imports, from_imports, visitor)

    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare) and
                    isinstance(test.left, ast.Name) and
                    test.left.id == "__name__"):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        callee, is_ext = visitor._resolve_call(child)
                        if callee and callee not in PYTHON_BUILTINS:
                            visitor.calls.append(CallEdge(
                                caller="__main__",
                                callee=callee,
                                file=file_path,
                                line=getattr(child, "lineno", 0),
                                is_external=is_ext,
                            ))

    return ParsedModule(
        file_path=file_path,
        module_name=module_name,
        imports=imports,
        from_imports=from_imports,
        functions=visitor.functions,
        calls=visitor.calls,
        global_calls=global_calls,
    )


def parse_directory(directory: str, verbose: bool = True) -> list[ParsedModule]:
    if verbose:
        print("\n╔══════════════════════════════════════════════╗")
        print("║     MODULE 2: Code Parsing Engine (AST)      ║")
        print("╚══════════════════════════════════════════════╝")

    py_files = []
    skip_dirs = {"__pycache__", ".git", "venv", ".venv", "node_modules",
                 ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
                 "egg-info", ".eggs"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))

    if verbose:
        print(f"\n  [*] Discovered {len(py_files)} Python source file(s)")

    parsed_modules = []
    for fpath in py_files:
        if verbose:
            rel = os.path.relpath(fpath, directory)
            print(f"  → Parsing {rel}...", end=" ")

        mod = parse_file(fpath)
        if mod:
            parsed_modules.append(mod)
            if verbose:
                n_fn = len(mod.functions)
                n_calls = len(mod.calls)
                n_global = len(mod.global_calls)
                extra = f", {n_global} global" if n_global else ""
                print(f"✓  ({n_fn} functions, {n_calls} calls{extra})")
        else:
            if verbose:
                print("✗ (skipped)")

    total_funcs = sum(len(m.functions) for m in parsed_modules)
    total_calls = sum(len(m.calls) for m in parsed_modules)
    total_global = sum(len(m.global_calls) for m in parsed_modules)
    entry_points = [fn.qualified_name for m in parsed_modules
                    for fn in m.functions if fn.is_entry_point]

    if verbose:
        print(f"\n  [✓] Parsing complete.")
        print(f"      Functions defined : {total_funcs}")
        print(f"      Call edges found  : {total_calls}")
        print(f"      Global-scope calls: {total_global}")
        print(f"      Entry points      : {entry_points or ['(none detected)']}")

    return parsed_modules
