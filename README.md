# ReachScan v2.0 — Automated Reachability Analysis for Dependency Security -- only demo version given, working on the product.

**Static call graph analysis engine that classifies CVEs as Reachable (must fix)
or Unreachable (skip), dramatically reducing SCA alert fatigue.**

---

## Quick Start

```bash
# 1. Install scanner dependencies
pip install -r reachscan/requirements.txt

# 2. Run in offline/demo mode against the sample vulnerable app
python reachscan/scanner.py vuln_app/ --no-network --out reports/report.html --json

# 3. Run with live OSV.dev API
python reachscan/scanner.py vuln_app/ --out reports/report.html --json

# 4. Graph-only mode (export call graph without vuln scanning)
python reachscan/scanner.py vuln_app/ --graph-only --dot reports/callgraph.dot

# 5. Filter by severity threshold
python reachscan/scanner.py vuln_app/ --no-network --severity HIGH
```

---

## Project Structure

```
reachscan/                  ← Scanner engine (v2.0 refactor)
├── scanner.py              ← Thin CLI entry point
├── config.py                ← All settings (env-overridable)
├── requirements.txt         ← networkx only (zero extra deps)
├── core/                    ← Engine implementations
│   ├── parser/              ← LanguageParser interface + AST Python parser
│   ├── graph/               ← GraphBuilder + DOT/JSON export
│   ├── reachability/        ← ReachabilityEngine (entry→sink classification)
│   ├── resolver/            ← Package-aware sink/import matching
│   ├── reporting/           ← Reporter interface + HTML/JSON + template
│   └── scoring/             ← Severity / CVSS classification
├── providers/               ← Vulnerability data sources (OSV, mock) + manifests
├── cache/                   ← Caching interface/manager (designed, disabled)
├── cli/                     ← Argument parsing + thin ScanEngine orchestrator
├── models/                  ← Plain-data dataclasses (no logic)
├── utils/                   ← Logging + exception hierarchy
└── tests/                   ← stdlib unittest suite (48 tests)
    └── ARCHITECTURE (dooc): docs/ARCHITECTURE.md

vuln_app/                   ← Intentionally vulnerable scan target
├── requirements.txt        ← Pinned to vulnerable versions
├── app.py                  ← Main entry point (orchestrates all modules)
├── config.py               ← yaml.load() without SafeLoader  [CVE-2020-14343]
├── image_handler.py        ← Image.open() no bomb check       [CVE-2022-22817]
├── web_utils.py            ← requests + Jinja2 Environment    [CVE-2023-32681, CVE-2024-34064]
└── data_processor.py       ← numpy.load allow_pickle=True     [CVE-2021-41496]
```
## v2.0 Improvements

### Critical Bug Fixes
- **Fixed sink matching algorithm** — `numpy.load` no longer falsely matches `yaml.load`
  (package-aware, score-based matching prevents cross-package false positives)
- **Fixed `requests.get` matching `os.environ.get`** — stdlib calls are properly filtered
- **Python 3.12+ / 3.14 compatibility** — removed deprecated `ast.Str` usage

### New Features
- **CVSS v3.1 scoring** — proper vector parsing with numeric scores
- **Fix version tracking** — tells developers what version to upgrade to
- **Multi-manifest support** — `requirements.txt`, `Pipfile`, `pyproject.toml`
- **30+ library signatures** — expanded sink database (Flask, Django, subprocess, etc.)
- **Graph statistics** — density, fan-out, connected components, isolated nodes
- **DOT export** — `--dot` flag for Graphviz visualization
- **Severity filtering** — `--severity HIGH` to focus on critical issues
- **Graph-only mode** — `--graph-only` to just export the call graph
- **Interactive HTML report** — D3.js call graph, search/filter, collapsible cards
- **Stdlib/builtin filtering** — removes noise from graph (45 → 34 nodes in demo)

---

## Pipeline Architecture

```
requirements.txt / Pipfile / pyproject.toml
       │
       ▼
┌─────────────────┐   ┌────────────────────┐
│  providers/     │   │  providers/manifest │
│  (OSV | mock)   │◄──┤  parse any manifest │
└────────┬────────┘   └────────────────────┘
         │
         ▼
┌─────────────────┐  .py files → AST
│  core/parser/   │  FunctionNode, CallEdge, decorators
└────────┬────────┘
         │
         ▼
┌─────────────────┐  DiGraph (filtered)
│  core/graph/    │  nodes=functions, edges=calls, stats
└────────┬────────┘
         │
         ▼
┌─────────────────┐  Package-aware sink matching
│ core/resolver/  │  import/sink knowledge
└────────┬────────┘
         │
         ▼
┌─────────────────┐  core/scoring → severity
│ core/reachability│  Entry.Point → Sink?
└────────┬────────┘
         │
         ▼
┌─────────────────┐  Reporter (HTML | JSON)
│ core/reporting/ │  Embedded graph + filter
└─────────────────┘
```

For full detail see **[`reachscan/docs/ARCHITECTURE.md`](reachscan/docs/ARCHITECTURE.md)** —
architecture diagram, execution flow, module dependency graph, per-module
explanation and the justification for every design decision.

`cli/pipeline.py` is the only coordinator; `scanner.py` is a thin entry point.
All reachability/parsing/scoring logic is isolated in `core/` and `providers/`.

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.x | Core implementation |
| AST Parsing | `ast` (stdlib) | Static code analysis |
| Graph Engine | `networkx` | Directed call graph + pathfinding |
| Vuln Database | OSV.dev JSON API | CVE/GHSA vulnerability data |
| Visualization | D3.js (embedded) | Interactive call graph in report |
| Report | HTML/CSS/JS | Self-contained security report |
