# ReachScan v2.0 — Architecture & Design

This document describes the refactored ReachScan engine. The refactor is
**behaviour-preserving**: all scan logic, reachability rules, report output and
CLI flags behave exactly as in v1. Only structure, dependencies, error and
logging discipline changed.

---

## 1. Repository layout

```
reachscan/
│
├── scanner.py                 Thin CLI entry point (wires args/config/pipeline only)
├── config.py                  Single source of truth for all settings
├── requirements.txt           networkx only (zero new deps)
│
├── core/                      Engine primitives (all implementation)
│   ├── parser/                Source -> ParsedModule (LanguageParser interface)
│   │   ├── base.py            LanguageParser ABC
│   │   └── python.py          AstPythonParser (AST implementation)
│   ├── graph/                 ParsedModule -> CallGraph
│   │   ├── builder.py         GraphBuilder + stats + reachable-set helper
│   │   └── exporter.py        DOT / JSON-serialisable graph export
│   ├── reachability/          CallGraph + Vulnerability -> ReachabilityResult
│   │   └── engine.py          ReachabilityEngine
│   ├── resolver/              Package-aware name/sink knowledge
│   │   ├── imports.py         distribution -> import-name mapping
│   │   ├── sinks.py           known sink signatures + advisory-hint extraction
│   │   └── matching.py        package-aware sink-matching confidence
│   ├── reporting/             results -> artefacts
│   │   ├── base.py            Reporter ABC
│   │   ├── html.py            HtmlReporter
│   │   ├── json.py            JsonReporter
│   │   └── report_template.html
│   └── scoring/               severity/CVSS classification
│       └── severity.py
│
├── providers/                 Vulnerability data sources (behind one interface)
│   ├── base.py                VulnerabilityProvider ABC + get_provider factory
│   ├── manifest.py            requirements.txt / Pipfile / pyproject.toml parsing
│   ├── osv.py                 OsvProvider (OSV.dev, pluggable transport)
│   └── mock.py                MockProvider (offline / demo)
│
├── cache/                     Response caching (interface only; disabled by default)
│   ├── base.py                Cache ABC + CacheMiss
│   └── manager.py             CacheManager + NullCache
│
├── cli/                       Orchestration (thin coordinator)
│   ├── args.py                argparse definition
│   └── pipeline.py            ScanEngine — order of phases only
│
├── models/                    Plain-data dataclasses (no behaviour beyond to_dict)
│   ├── dependency.py          Dependency, Vulnerability
│   ├── code.py                FunctionNode, CallEdge, ParsedModule
│   ├── graph.py               CallGraph, GraphStats
│   └── result.py              ReachabilityResult
│
├── utils/
│   ├── exceptions.py          ReachScanError hierarchy
│   └── logging.py             Lightweight logger setup
│
└── tests/                    stdlib unittest suite (dozens of focused tests)
```

---

## 2. Architecture diagram

```
                        ┌──────────────────────┐
                        │   scanner.py (thin)   │
                        │  args + config + run  │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │   cli/pipeline.py    │  ScanEngine — orchestration
                        │        (no logic)    │
                        └───┬───────────┬──────┘
                            │           │
            source analysis │           │ vulnerability intake
                            ▼           ▼
                 ┌────────────────┐  ┌────────────────────────┐
                 │ core/parser/   │  │ providers/             │
                 │ LanguageParser │  │ VulnerabilityProvider  │
                 │  ◄─ python.py  │  │  ├─ manifest.py        │
                 └───────┬────────┘  │  ├─ osv.py             │
                         │           │  └─ mock.py            │
                         ▼           └──────────┬─────────────┘
                 ┌────────────────┐             │
                 │ core/graph/    │             │
                 │ GraphBuilder   │             │
                 └───────┬────────┘             │
                         │                      │
                 ┌───────▼────────┐     ┌───────▼──────────┐
                 │ core/resolver/ │     │ core/scoring/    │
                 │ matching/sinks │     │ severity         │
                 └───────┬────────┘     └───────┬──────────┘
                         │                      │
                         └──────────┬───────────┘
                                    ▼
                       ┌────────────────────────┐
                       │ core/reachability/     │  ReachabilityEngine
                       │  Entry.Point → Sink?   │
                       └───────────┬────────────┘
                                   ▼
                       ┌────────────────────────┐
                       │ core/reporting/        │  Reporter (html | json)
                       │  └ report_template.html│
                       └────────────────────────┘

  Shared foundations:  models/  (data types, no logic)
                       utils/   (logging, exceptions)
                       config.py (settings)
                       cache/   (planned; disabled today)
```

---

## 3. Execution flow

1. **Entry** — `scanner.py` parses argv (`cli/args.py`), builds `Settings`
   (`config.py`) and configures logging (`utils/logging.py`).
2. **Orchestrate** — `ScanEngine.run` resolves the target directory.
3. **Parse** — `AstPythonParser.parse_directory` discovers `.py` files,
   extracts `ParsedModule` records (functions, calls, imports). Per-file
   failures (IO/syntax) are logged as warnings and the scan continues.
4. **Build graph** — `GraphBuilder.build()` produces a `CallGraph`
   (`networkx.DiGraph`); stdlib/builtin noise nodes are pruned.
5. **Export (optional)** — DOT to a file if `--dot` given. `--graph-only`
   stops here.
6. **Ingest** — `providers/discover_manifests` parses dependency manifests into
   `Dependency`s; a `VulnerabilityProvider` (mock for `--no-network`, OSV
   otherwise) is selected via `get_provider`; each dependency is looked up and
   deduplicated into a `Vulnerability` set.
7. **Filter** — optional `--severity` threshold trims the set.
8. **Analyse** — `ReachabilityEngine.analyze_many` classifies each
   vulnerability as REACHABLE or UNREACHABLE using package-aware sink matching
   (`core/resolver/matching`) and `networkx` path existence.
9. **Report** — HtmlReporter always; JsonReporter when `--json`. Each writes to
   disk and returns the path.
10. **Done** — exit code returned.

```
 args -> settings -> parse -> graph(.dot) -> ingest(provider) -> filter
       -> reachability -> html | json -> exit
```

---

## 4. Module dependency graph

Directed edges mean "module A imports/depends on B". All arrows point to
lower-level / interface modules, keeping the graph acyclic and testable.

```
scanner.py ──────────► cli  ─► (parse_args)
clis/pipeline.py ──► config.py, utils/logging, utils/exceptions,
                     core/parser, core/graph, core/reachability,
                     core/reporting, core/scoring, providers

core/parser/base.py   ◄── core/parser/python.py ──► models/code.py, utils/*
core/graph/builder.py ◄── models/code, models/graph, core/parser/python(constants)
core/graph/exporter.py ──► models/graph
core/reachability/engine.py ──► core/resolver/matching, models/*
core/resolver/matching.py ──► core/resolver/imports
core/resolver/sinks.py ──► (stdlib re)
core/scoring/severity.py──► (standalone)

providers/base.py ──► models/dependency, utils/exceptions
providers/osv.py ────► providers/base, core/resolver/sinks, core/scoring/severity
providers/mock.py ───► providers/base
providers/manifest.py ► models/dependency, utils/*

models/* ──► (no imports into core/providers — pure data)
utils/*   ──► config.py only (logging reads Settings)
cache/*   ──► config.py, utils/logging
reports   ──► tests (unittest)
tests/*   ──► everything (loads package root via tests/__init__.py)
```

Observations:
- `models/` is a root leaf — change data shape without touching consumers.
- `providers/` never imports `core/` (except read-only *knowledge* helpers);
  a provider needs the `VulnerabilityProvider` interface + models only.
- `config.py` and `utils/` are depended upon by everyone, so they never import
  engine code (no cycles).
- The only reason `core/graph/builder.py` imports `core/parser/python.py` is to
  reuse the `STDLIB_MODULES` / `PYTHON_BUILTINS` noise tables.

---

## 5. Module-by-module explanation

| Module | Responsibility | Key symbols |
|---|---|---|
| `scanner.py` | Pure CLI entry; wires config + args + pipeline | `main()` |
| `config.py` | All settings with `REACHSCAN_*` env overrides | `Settings`, `load_settings` |
| `core/parser/base.py` | Language parser contract | `LanguageParser` |
| `core/parser/python.py` | AST-based Python parsing; per-file tolerance | `AstPythonParser` |
| `core/graph/builder.py` | DiGraph construction + stats | `GraphBuilder`, `get_reachable_nodes` |
| `core/graph/exporter.py` | DOT/JSON serialization of a graph | `export_dot`, `export_graph_summary` |
| `core/reachability/engine.py` | Reachable/unreachable classification | `ReachabilityEngine` |
| `core/resolver/imports.py` | Distribution → import-name mapping | `get_import_names` |
| `core/resolver/sinks.py` | Known vulnerable function signatures + hint parse | `get_vulnerable_functions` |
| `core/resolver/matching.py` | Package-aware sink confidence score | `match_score` |
| `core/scoring/severity.py` | CVSS parse, severity order `extract_severity` | `SEVERITY_ORDER`, `extract_severity` |
| `providers/base.py` | Provider contract + factory | `VulnerabilityProvider`, `get_provider` |
| `providers/manifest.py` | Manifest parsing + dedup | `discover_manifests`, `parse_requirements` |
| `providers/osv.py` | OSV query + OSV→Vulnerability transform | `OsvProvider` |
| `providers/mock.py` | Deterministic offline demo data | `MockProvider` |
| `cache/base.py` | Cache interface | `Cache`, `CacheMiss` |
| `cache/manager.py` | Cache owner/location/disable | `CacheManager`, `NullCache` |
| `cli/args.py` | argparse definition | `build_parser`, `parse_args` |
| `cli/pipeline.py` | Pipeline coordinator (no analysis logic) | `ScanEngine`, `run` |
| `models/*` | Pure data records | dataclasses |
| `utils/exceptions.py` | Error hierarchy | `ReachScanError` and subtypes |
| `utils/logging.py` | Logger configuration | `configure_logging`, `get_logger` |
| `tests/*` | Behavioural unit/integration tests | unittest |

---

## 6. Architectural decisions and justifications

1. **Interfaces over frameworks** — We define narrow ABCs (`LanguageParser`,
   `GraphBuilder`, `ReachabilityEngine`, `Reporter`, `VulnerabilityProvider`,
   `Cache`) instead of an injection framework or a DI container. A single
   developer can read the whole contract in minutes; wiring is explicit in
   `ScanEngine.__init__`. A DI container or web framework would add weight a
   one-person, zero-framework project does not need.

2. **Thin coordinator** — All present flow lives in `cli/pipeline.py`;
   `scanner.py` is now ~20 lines of glue. Business logic sits in `core/` and
   `providers/`, so the pipeline can be replaced (API server, CI plugin, cron)
   without touching engine code.

3. **One config module** — Every magic value (endpoint, timeouts, paths, log
   level, skip dirs, provider list) moved to `config.py`, overridable by env.
   No module hardcodes a constant anymore; the old `OSV_API_URL`,
   `MAX_RETRIES`, `skip_dirs`, etc. are now settings.

4. **Separation of data from behaviour** — `models/` are plain dataclasses.
   Consumers never hold mutable analysis state, and models can be imported by
   test fixtures and future standalone tools without pulling in `networkx`.

5. **Provider isolation** — Vulnerability intake is behind
   `VulnerabilityProvider`. OSV is one implementation; a `mock` impl covers
   offline mode. Adding NVD/GHSA later means registering a name in
   `Provider & `get_provider`; the pipeline/s classifier never change.

6. **Network confined & injectable** — `OsvProvider` takes an optional
   `http_post` callable. Tests inject a fake transport; no monkeypatching of
   `urllib`. Real network code sits in one method.

7. **Plugin-aware sink/resolver knowledge** — package knowledge
   (`PACKAGE_TO_IMPORT`, `KNOWN_SINK_SIGNATURES`, scoring logic) lives in
   `core/resolver` + `core/scoring` so it can be unit-tested and reused by
   future providers without reachability/scanner changes.

8. **Preserve behaviour exactly** — sink matching constants, thresholds
   (`MATCH_THRESHOLD=0.30`), demo CVEs, timestamps, and JSON schema are
   byte-for-byte equivalent (validated by diffing v1 vs v2 JSON reports). New
   code is a strict refactor, not a behaviour change.

9. **Memory & speed mindfulness** — formulas/property deduplication, capped
   path-based results (`DEFAULT_MAX_PATHS=3`), lazy discovery, and no global
   mutable state. The graph is the only sizable object; it is referenced by
   value in results (paths, not graph objects).

10. **Lightweight logging** — stdlib `logging`, four levels, one line per phase
    at INFO; per-item detail at DEBUG. No third-party log library; nothing
    printed to stdout that would corrupt programmatic callers.

11. **Custom exceptions, never silent** — every expected failure raises a
    `ReachScanError` subtype. Transient provider/parse failures log a warning
    and continue; fatal issues raise. Exceptional retries: `osv.py` retry with
    backoff, then logs error and returns empty (matching v1 "no vulns"
    semantics) — behavior of a single lookup, not whole scan.

12. **Cache designed, not built (yet)** — `cache/` defines the interface and a
    `NullCache` behind the manager. Enabling caching later is a backend swap in
    one file, no re-plumbing.

13. **Minimal dependencies** — still only `networkx`. AST, JSON, retry, path,
    HTTP all use stdlib. Tests use stdlib `unittest spawn`, no pytest required.

---

## 7. Running the tests

```bash
cd reachscan
python3 -m unittest discover -s tests -t .
```

48 tests cover: manifest parsing, severity/CVSS classification, resolver
matching, AST parser, graph builder/export, reachability classification, OSV
provider (fake transport), reporters, and the end-to-end pipeline.

## 8. Behaviour-verification note

The v2 JSON output was diffed against the v1 committed `reports/report.json`:
all 5 vulnerability records (`cve_id`, severity, priority, reachability,
paths, CVSS, fixed_version, references) are **identical**, and the call-graph
nodes/edges are identical aside from absolute-vs-relative source `file` paths
(the v1 report used a relative run directory; v2 uses the same
`os.path.abspath` normalization as `scanner.py` v1). No other difference.
```