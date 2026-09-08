"""Known taint-source signatures — mirrors core/resolver/sinks.py shape.

Each source is a pattern that, when matched against an expression in the AST,
identifies externally-influenced data entering the program.  The lookup helper
returns ``None`` when no pattern matches, following the same convention as
``core/resolver/sinks.py``'s existing helpers.
"""

from __future__ import annotations

from models.dataflow import TaintOrigin
from core.parser.python import ENTRY_POINT_NAMES, ENTRY_POINT_DECORATORS

# ── Source signature tables ──────────────────────────────────────────────────
# Mapping of expression-pattern substrings to TaintOrigin, grouped by origin
# category.  The lookup iterates these in order and returns the first match.

KNOWN_SOURCE_SIGNATURES: dict[str, list[str]] = {
    # os.environ / os.getenv
    "env_var": [
        "os.environ.get",
        "os.environ",
        "os.getenv",
        "environ.get",
        "environ",
    ],
    # sys.argv / argparse
    "cli_arg": [
        "sys.argv",
        "argparse.ArgumentParser",
        "parser.parse_args",
        "args.",                  # attributes off an argparse Namespace
    ],
    # stdin
    "stdin": [
        "input(",
        "sys.stdin",
    ],
    # file reads
    "file_read": [
        ".read(",
        ".readlines(",
        ".readline(",
        "open(",
    ],
    # Flask / HTTP request objects
    "http_request": [
        "request.args",
        "request.json",
        "request.form",
        "request.get_json",
        "request.data",
        "request.values",
        "request.files",
        "request.headers",
    ],
}

# Reverse mapping: category string → TaintOrigin enum value.
_CATEGORY_TO_ORIGIN: dict[str, TaintOrigin] = {
    "env_var":      TaintOrigin.ENV_VAR,
    "cli_arg":      TaintOrigin.CLI_ARG,
    "stdin":        TaintOrigin.STDIN,
    "file_read":    TaintOrigin.FILE_READ,
    "http_request": TaintOrigin.HTTP_REQUEST,
}


def classify_source(expr_repr: str, context: dict | None = None) -> TaintOrigin | None:
    """Return the ``TaintOrigin`` for an expression, or ``None`` if no match.

    Parameters
    ----------
    expr_repr:
        A short string representation of the expression (e.g. the source text
        of an ``ast.Name`` or ``ast.Attribute`` node).
    context:
        Optional mapping with extra information.  Recognised keys:

        * ``"is_entry_param"`` — if ``True``, the variable is a parameter of
          a function whose name is in ``ENTRY_POINT_NAMES`` or whose
          decorators intersect ``ENTRY_POINT_DECORATORS``.
        * ``"function_name"`` — the unqualified function name, checked against
          ``ENTRY_POINT_NAMES``.
        * ``"decorators"`` — a list of decorator strings, checked against
          ``ENTRY_POINT_DECORATORS``.
    """
    context = context or {}

    # 1. Entry-point function parameter → FUNCTION_PARAM
    if context.get("is_entry_param"):
        return TaintOrigin.FUNCTION_PARAM

    fn_name = context.get("function_name", "")
    decorators = context.get("decorators", [])
    if fn_name in ENTRY_POINT_NAMES or any(d in ENTRY_POINT_DECORATORS for d in decorators):
        if context.get("is_param"):
            return TaintOrigin.FUNCTION_PARAM

    # 2. Pattern match against known source signatures
    for category, patterns in KNOWN_SOURCE_SIGNATURES.items():
        for pattern in patterns:
            if pattern in expr_repr:
                return _CATEGORY_TO_ORIGIN[category]

    return None


def is_entry_point_function(function_name: str,
                            decorators: list[str] | None = None) -> bool:
    """Check if a function qualifies as an entry point (taint root).

    Reuses ``ENTRY_POINT_NAMES`` and ``ENTRY_POINT_DECORATORS`` from the
    parser — they are not redefined here.
    """
    if function_name in ENTRY_POINT_NAMES or function_name == "main":
        return True
    if decorators:
        for dec in decorators:
            if dec in ENTRY_POINT_DECORATORS:
                return True
            for ep_dec in ENTRY_POINT_DECORATORS:
                if dec.endswith(ep_dec.split(".")[-1]) and "route" in dec:
                    return True
    return False
