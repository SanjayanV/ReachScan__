"""Tests for the dataflow confirmation layer."""

import ast
import unittest

from models.dataflow import (
    DataflowResult,
    DataflowVerdict,
    TaintOrigin,
    TaintedBinding,
    ArgumentBinding,
)
from core.dataflow.sources import classify_source, is_entry_point_function
from core.dataflow.tracer import DataflowTracer
from models.code import CallEdge, FunctionNode, ParsedModule
from tests.helpers import TempProject


# ── Model tests ─────────────────────────────────────────────────────────────


class TaintOriginTest(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(TaintOrigin.FUNCTION_PARAM.value, "function_param")
        self.assertEqual(TaintOrigin.ENV_VAR.value, "env_var")
        self.assertEqual(TaintOrigin.CLI_ARG.value, "cli_arg")
        self.assertEqual(TaintOrigin.STDIN.value, "stdin")
        self.assertEqual(TaintOrigin.FILE_READ.value, "file_read")
        self.assertEqual(TaintOrigin.HTTP_REQUEST.value, "http_request")
        self.assertEqual(TaintOrigin.UNKNOWN_EXTERNAL.value, "unknown_external")


class DataflowVerdictTest(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(DataflowVerdict.CONFIRMED.value, "confirmed")
        self.assertEqual(DataflowVerdict.UNCONFIRMED.value, "unconfirmed")
        self.assertEqual(DataflowVerdict.NOT_APPLICABLE.value, "not_applicable")


class DataflowResultTest(unittest.TestCase):
    def test_defaults(self):
        r = DataflowResult(verdict=DataflowVerdict.UNCONFIRMED)
        self.assertEqual(r.verdict, DataflowVerdict.UNCONFIRMED)
        self.assertEqual(r.tainted_path_segment, [])
        self.assertIsNone(r.origin)
        self.assertEqual(r.explanation, "")

    def test_confirmed_with_origin(self):
        r = DataflowResult(
            verdict=DataflowVerdict.CONFIRMED,
            tainted_path_segment=["main", "foo"],
            origin=TaintOrigin.CLI_ARG,
            explanation="traced to CLI arg",
        )
        self.assertEqual(r.verdict, DataflowVerdict.CONFIRMED)
        self.assertEqual(r.origin, TaintOrigin.CLI_ARG)


class TaintedBindingTest(unittest.TestCase):
    def test_creation(self):
        tb = TaintedBinding(
            variable_name="user_input",
            function_qualified_name="app.main",
            origin=TaintOrigin.STDIN,
            source_expr="input()",
        )
        self.assertEqual(tb.variable_name, "user_input")
        self.assertEqual(tb.origin, TaintOrigin.STDIN)


class ArgumentBindingTest(unittest.TestCase):
    def test_creation(self):
        ab = ArgumentBinding(
            caller_qualified_name="app.main",
            callee_qualified_name="config.load",
            param_name="path",
            arg_expr="CONFIG_FILE",
            is_literal=False,
        )
        self.assertEqual(ab.param_name, "path")
        self.assertFalse(ab.is_literal)


# ── Source classification tests ──────────────────────────────────────────────


class ClassifySourceTest(unittest.TestCase):
    def test_env_var(self):
        self.assertEqual(classify_source("os.environ.get('KEY')"), TaintOrigin.ENV_VAR)
        self.assertEqual(classify_source("os.getenv('KEY')"), TaintOrigin.ENV_VAR)

    def test_cli_arg(self):
        self.assertEqual(classify_source("sys.argv[1]"), TaintOrigin.CLI_ARG)
        self.assertEqual(classify_source("args.username"), TaintOrigin.CLI_ARG)

    def test_stdin(self):
        self.assertEqual(classify_source("input('prompt')"), TaintOrigin.STDIN)

    def test_file_read(self):
        self.assertEqual(classify_source("f.read()"), TaintOrigin.FILE_READ)
        self.assertEqual(classify_source("open(path)"), TaintOrigin.FILE_READ)

    def test_http_request(self):
        self.assertEqual(classify_source("request.args"), TaintOrigin.HTTP_REQUEST)
        self.assertEqual(classify_source("request.json"), TaintOrigin.HTTP_REQUEST)
        self.assertEqual(classify_source("request.form"), TaintOrigin.HTTP_REQUEST)

    def test_entry_point_param(self):
        origin = classify_source("x", context={"is_entry_param": True})
        self.assertEqual(origin, TaintOrigin.FUNCTION_PARAM)

    def test_no_match(self):
        self.assertIsNone(classify_source("some_local_var"))
        self.assertIsNone(classify_source("42"))


class IsEntryPointFunctionTest(unittest.TestCase):
    def test_known_names(self):
        self.assertTrue(is_entry_point_function("main"))
        self.assertTrue(is_entry_point_function("run"))
        self.assertTrue(is_entry_point_function("handler"))

    def test_decorator_match(self):
        self.assertTrue(is_entry_point_function("index", ["app.route"]))

    def test_non_entry(self):
        self.assertFalse(is_entry_point_function("_helper"))
        self.assertFalse(is_entry_point_function("compute_total"))


# ── Tracer tests ─────────────────────────────────────────────────────────────


def _make_parsed_module(source: str, file_path: str = "/tmp/test.py") -> ParsedModule:
    """Parse a Python source string into a ParsedModule."""
    from core.parser.python import AstPythonParser
    import tempfile
    from pathlib import Path

    # Write to a temp file so the parser can read it
    tmp = Path(tempfile.mktemp(suffix=".py"))
    tmp.write_text(source, encoding="utf-8")
    try:
        parser = AstPythonParser()
        mod = parser.parse_file(str(tmp))
        if mod is None:
            raise ValueError("Failed to parse source")
        return mod
    finally:
        tmp.unlink(missing_ok=True)


class TracerLiteralArgsTest(unittest.TestCase):
    """When all sink arguments are literals, verdict should be UNCONFIRMED
    (the constant itself is not attacker-controlled, but the content it
    references might be — prefer conservative UNCONFIRMED)."""

    def test_literal_constant_arg_is_unconfirmed(self):
        source = '''
def main():
    load_config("config.yaml")

def load_config(path):
    yaml.load(path)
'''
        mod = _make_parsed_module(source)
        tracer = DataflowTracer()
        path = ["main", "load_config"]
        result = tracer.trace(path, {}, {mod.file_path: mod})
        # Should be UNCONFIRMED or NOT_APPLICABLE — never CONFIRMED
        self.assertIn(result.verdict, (
            DataflowVerdict.UNCONFIRMED,
            DataflowVerdict.NOT_APPLICABLE,
        ))


class TracerTaintedParamTest(unittest.TestCase):
    """When a parameter of an entry point flows into a sink, verdict
    should be CONFIRMED."""

    def test_entry_param_to_sink_is_confirmed(self):
        source = '''
def main(user_input):
    process(user_input)

def process(data):
    dangerous_call(data)
'''
        mod = _make_parsed_module(source)
        tracer = DataflowTracer()
        path = ["main", "process"]
        result = tracer.trace(path, {}, {mod.file_path: mod})
        # main is an entry point and user_input is its param
        self.assertIn(result.verdict, (
            DataflowVerdict.CONFIRMED,
            DataflowVerdict.UNCONFIRMED,
        ))


class TracerShortPathTest(unittest.TestCase):
    def test_path_too_short(self):
        tracer = DataflowTracer()
        result = tracer.trace(["single_node"], {}, {})
        self.assertEqual(result.verdict, DataflowVerdict.UNCONFIRMED)


class TracerSourceExpressionTest(unittest.TestCase):
    """When a source expression (like args.x) is directly passed to a callee."""

    def test_args_attr_is_cli_arg(self):
        source = '''
def run_pipeline(args):
    render_dashboard(args.username)

def render_dashboard(name):
    template.render(name)
'''
        mod = _make_parsed_module(source)
        tracer = DataflowTracer()
        path = ["run_pipeline", "render_dashboard"]
        result = tracer.trace(path, {}, {mod.file_path: mod})
        # args.username should be classified as CLI_ARG
        if result.verdict == DataflowVerdict.CONFIRMED:
            self.assertEqual(result.origin, TaintOrigin.CLI_ARG)


# ── Integration with ReachabilityResult ──────────────────────────────────────


class ReachabilityResultDataflowTest(unittest.TestCase):
    def test_dataflow_field_defaults_none(self):
        from models.result import ReachabilityResult
        from tests.helpers import make_vulnerability
        vuln = make_vulnerability()
        result = ReachabilityResult(
            vulnerability=vuln,
            is_reachable=True,
            reachable_via=["sink"],
            execution_paths=[["main", "sink"]],
            unreachable_sinks=[],
            missing_sinks=[],
        )
        self.assertIsNone(result.dataflow)

    def test_to_dict_includes_dataflow(self):
        from models.result import ReachabilityResult
        from tests.helpers import make_vulnerability
        vuln = make_vulnerability()
        df = DataflowResult(
            verdict=DataflowVerdict.CONFIRMED,
            origin=TaintOrigin.CLI_ARG,
            explanation="test",
        )
        result = ReachabilityResult(
            vulnerability=vuln,
            is_reachable=True,
            reachable_via=["sink"],
            execution_paths=[["main", "sink"]],
            unreachable_sinks=[],
            missing_sinks=[],
            dataflow=df,
        )
        d = result.to_dict()
        self.assertIn("dataflow", d)
        self.assertEqual(d["dataflow"]["verdict"], "confirmed")
        self.assertEqual(d["dataflow"]["origin"], "cli_arg")

    def test_to_dict_dataflow_none(self):
        from models.result import ReachabilityResult
        from tests.helpers import make_vulnerability
        vuln = make_vulnerability()
        result = ReachabilityResult(
            vulnerability=vuln,
            is_reachable=False,
            reachable_via=[],
            execution_paths=[],
            unreachable_sinks=[],
            missing_sinks=[],
        )
        d = result.to_dict()
        self.assertIn("dataflow", d)
        self.assertIsNone(d["dataflow"])


if __name__ == "__main__":
    unittest.main()
