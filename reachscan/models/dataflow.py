"""Models produced by the intraprocedural/interprocedural dataflow pass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TaintOrigin(str, Enum):
    """Where a piece of tainted data enters the program."""
    FUNCTION_PARAM = "function_param"      # param of an entry-point function
    ENV_VAR = "env_var"                    # os.environ.get / os.getenv
    CLI_ARG = "cli_arg"                    # sys.argv, argparse result attrs
    STDIN = "stdin"                        # input()
    FILE_READ = "file_read"                # open(...).read()
    HTTP_REQUEST = "http_request"          # flask request.args/json/form etc.
    UNKNOWN_EXTERNAL = "unknown_external"  # matched a source signature generically


@dataclass
class TaintedBinding:
    """One variable, in one function scope, marked as tainted."""
    variable_name: str
    function_qualified_name: str
    origin: TaintOrigin
    source_expr: str = ""   # short repr of the originating expression, for reporting


@dataclass
class ArgumentBinding:
    """Maps a call site's argument expression to the callee's parameter name."""
    caller_qualified_name: str
    callee_qualified_name: str
    param_name: str
    arg_expr: str            # source-text-ish repr, e.g. "config_path" or "'literal'"
    is_literal: bool         # True if arg is a Constant (never tainted)


class DataflowVerdict(str, Enum):
    CONFIRMED = "confirmed"          # traced attacker-controlled data to the sink arg
    UNCONFIRMED = "unconfirmed"      # reachable but could not confirm/deny taint
    NOT_APPLICABLE = "not_applicable"  # sink has no meaningful tainted parameter to check


@dataclass
class DataflowResult:
    """Attached to a ReachabilityResult; does not replace anything on it."""
    verdict: DataflowVerdict
    tainted_path_segment: list[str] = field(default_factory=list)  # qualified names
    origin: TaintOrigin | None = None
    explanation: str = ""   # one-line human-readable reason, for the report
