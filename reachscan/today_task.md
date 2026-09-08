# ReachScan — Dataflow Confirmation Layer (Spec for Opus)

**Goal:** Extend ReachScan's reachability engine to distinguish "sink is
topologically reachable" from "sink's dangerous parameter is fed by
attacker-influenceable data." This is an **additive** feature — no existing
behavior, CLI flags, report schema, or test expectations may change or break.

Read `reachscan/docs/ARCHITECTURE.md` first. Match its conventions exactly:
narrow ABCs, plain dataclasses in `models/`, knowledge-base modules under
`core/resolver/` style (this feature adds `core/dataflow/`, sibling to
`core/reachability/`), stdlib-only, `utils.logging.get_logger`, custom
exceptions from `utils/exceptions.py` where a failure is expected/recoverable.

---

## 1. Scope — what this IS and IS NOT

**IS:**
- Intraprocedural def-use tracking (assignments, parameter bindings) within a
  single function body, via `ast`.
- Interprocedural propagation *only* along call edges that are already part
  of an existing `all_simple_paths` result — i.e. we annotate paths the
  engine already found, we do not compute new graph traversals.
- A taint-source knowledge base (`core/dataflow/sources.py`), structurally
  mirroring `core/resolver/sinks.py`.
- A tri-state confirmation verdict attached to each `ReachabilityResult`,
  additive to the existing `is_reachable` bool.

**IS NOT (do not build):**
- No symbolic execution, no SMT solving, no full points-to analysis.
- No cross-file global variable taint tracking beyond simple param/arg
  binding at call sites.
- No dynamic/runtime PoC execution — this is static only.
- No changes to `core/reachability/engine.py`'s existing `analyze()` control
  flow beyond one additional call out to the new dataflow module. Its
  existing return contract (`is_reachable`, `reachable_via`,
  `execution_paths`, `match_confidence`, etc.) must be untouched — add
  fields, don't rename or remove any.

---

## 2. New models — `models/dataflow.py`

```python
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
```

---

## 3. New knowledge base — `core/dataflow/sources.py`

Mirror the shape of `core/resolver/sinks.py` (read that file first and match
its signature-matching style exactly — same kind of dict-of-lists constant,
same kind of lookup helper function name pattern).

Must cover at minimum:
- Parameters of any function where `FunctionNode.is_entry_point == True`
  (these are the taint roots — reuse the existing `ENTRY_POINT_NAMES` /
  `ENTRY_POINT_DECORATORS` sets from `core/parser/python.py`, do not
  redefine them — import and reuse).
- `os.environ.get`, `os.getenv`
- `sys.argv`
- `input()`
- `open(...).read()` / `.readlines()` (file contents = external data)
- Flask-style: `request.args`, `request.json`, `request.form`,
  `request.get_json`
- `argparse` — attributes read off the parsed `Namespace` object returned by
  `parser.parse_args()` (this is the one that actually matters for the demo
  app — `args.username` in `vuln_app/app.py` should resolve as CLI_ARG)

Provide a function `classify_source(expr_repr: str, context) -> TaintOrigin | None`
following the same "return None if no match" convention as
`core/resolver/sinks.py`'s existing helpers.

---

## 4. New module — `core/dataflow/tracer.py`

```python
class DataflowTracer:
    """Given a call-graph path (list of qualified function names) already
    found by ReachabilityEngine, determines whether the sink's dangerous
    argument traces back to a taint source somewhere along that path.

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
              parsed_modules: dict) -> DataflowResult:
        ...
```

Implementation notes for Opus:
- Reuse `ast` — you'll need the original AST or a lightweight re-parse per
  function (the existing `AstPythonParser` already parses everything once;
  either extend `ParsedModule`/`FunctionNode` to retain a reference to the
  function's AST node, OR re-parse lazily and cache by qualified name —
  your choice, pick whichever touches less existing code).
- If ambiguous (arg is a subscript, attribute chain, f-string, comprehension,
  etc. — anything beyond a bare `Name` or `Constant`), classify as
  `UNCONFIRMED`, never guess `CONFIRMED`. False negatives here are
  acceptable; false positives are not — the whole point of this feature is
  to raise confidence, not manufacture false certainty.
- Literal `Constant` arguments at every hop → `NOT_APPLICABLE` if the sink
  call itself is passed only literals, or fold into `UNCONFIRMED` if a
  non-sink hop along the path had a non-literal, non-traceable arg.

---

## 5. Wiring into `core/reachability/engine.py`

Add exactly one thing to `ReachabilityEngine.analyze()`: after
`unique_paths = self._dedupe_paths(all_paths)`, for each path in
`unique_paths`, call the tracer and attach the best (most-confirmed) verdict
found across paths to the result. Add a new field to
`ReachabilityResult` (in `models/result.py`):

```python
dataflow: DataflowResult | None = None
```

Default `None` so **every existing test in `tests/test_reachability.py`
still passes unmodified** — this is the hard constraint. Do not touch
existing test files. Add new ones instead: `tests/test_dataflow.py`.

---

## 6. Reporting

- `core/reporting/json.py`: add the `dataflow` field to whatever serializes
  `ReachabilityResult` — additive key, existing keys untouched.
- `core/reporting/html.py` / `report_template.html`: add a badge/tag next to
  each reachable CVE — "Dataflow: CONFIRMED" (red/strong), "UNCONFIRMED"
  (amber/neutral), or nothing if `NOT_APPLICABLE`. Do not restructure the
  existing template layout — additive DOM only.
- `core/scoring/severity.py`: do NOT change severity/CVSS scoring logic.
  Dataflow verdict is a separate signal, not a severity input, for this
  iteration.

---

## 7. Expected demo-app outcome (for your own validation, not a hard test)

Given `vuln_app/`, after this change:
- `CVE-2020-14343` (yaml.load) — `load_config(CONFIG_FILE)`, `CONFIG_FILE` is
  a module-level string constant → sink arg traces to a **Constant**, not a
  param → `UNCONFIRMED` (correctly: nothing here proves an attacker can
  supply the YAML content in this exact code path, even though it's
  reachable).
- `CVE-2024-34064` (Jinja2 xmlattr) — `render_dashboard(user_attrs, ...)`,
  `user_attrs["name"] = args.username` → `args.username` is an argparse
  CLI_ARG source → **CONFIRMED**.
- `CVE-2021-41496` (numpy) — already `UNREACHABLE` at the graph level, so
  dataflow is never invoked (`NOT_APPLICABLE`, short-circuited before the
  tracer runs at all).

This divergence (yaml.load UNCONFIRMED vs jinja2 CONFIRMED, despite both
being graph-REACHABLE today) is the entire point of the feature — it's your
proof this isn't cosmetic.

---

## 8. File change list (exhaustive — do not touch anything not listed)

**New files:**
- `reachscan/models/dataflow.py`
- `reachscan/core/dataflow/__init__.py`
- `reachscan/core/dataflow/sources.py`
- `reachscan/core/dataflow/tracer.py`
- `reachscan/tests/test_dataflow.py`

**Modified files (additive changes only, no removals/renames):**
- `reachscan/models/result.py` — add `dataflow` field
- `reachscan/models/code.py` — add whatever minimal field is needed to
  retain per-call argument info (e.g. `arg_reprs: list[str]` on `CallEdge`,
  or similar — your call, keep it minimal)
- `reachscan/core/parser/python.py` — capture argument expressions when
  building `CallEdge`s
- `reachscan/core/reachability/engine.py` — one call-out to the tracer per
  path, as described in §5
- `reachscan/core/reporting/json.py`, `html.py`, `report_template.html` —
  additive fields/badges only

**Do not touch:** `core/graph/`, `core/resolver/matching.py`,
`core/resolver/sinks.py` (read-only reference), `core/scoring/`,
`providers/`, `cli/`, `cache/`, `config.py`, any existing test file.

---

## 9. Definition of done

1. `python3 -m unittest discover -s tests -t .` — all 48 existing tests
   still pass, unmodified, plus new `test_dataflow.py` tests pass.
2. Running the demo command produces the divergent verdicts described in §7.
3. JSON report output is valid (existing keys unchanged) and contains the
   new `dataflow` object per result.
4. No new third-party dependency added (`requirements.txt` stays
   `networkx` only).

---

## Prompt to paste into Antigravity (Opus)

> Implement the attached spec (`reachscan-dataflow-spec.md`) against the
> `reachscan_project/reachscan` codebase in this workspace. Follow the file
> change list in §8 exactly — do not modify any file not listed there, and
> do not modify any existing test file. Read `docs/ARCHITECTURE.md` and
> `core/resolver/sinks.py` first to match existing code conventions
> (dataclass style, logging via `utils.logging.get_logger`, knowledge-base
> module shape). Implement in this order: (1) `models/dataflow.py`, (2)
> `core/dataflow/sources.py`, (3) argument-capture changes to
> `core/parser/python.py` and `models/code.py`, (4) `core/dataflow/tracer.py`,
> (5) wiring in `core/reachability/engine.py` and `models/result.py`, (6)
> reporting additions, (7) `tests/test_dataflow.py`. After implementation,
> run the full test suite and the demo scan against `vuln_app/`, and report
> the dataflow verdicts for all 4 reachable CVEs so I can confirm they match
> §7. Ask no clarifying questions — where the spec is ambiguous, follow the
> "IS NOT" boundaries in §1 and prefer UNCONFIRMED over guessing CONFIRMED.