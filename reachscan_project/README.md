# ReachScan v2.0 — Automated Reachability Analysis for Dependency Security

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
reachscan/                  ← Scanner engine
├── scanner.py              ← CLI entry point (v2.0)
├── requirements.txt        ← networkx only (zero extra deps)
└── modules/
    ├── ingestion.py        ← Module 1: OSV.dev API + multi-manifest parsing
    ├── parser.py           ← Module 2: AST → FunctionNode + CallEdge extraction
    ├── graph.py            ← Module 3: NetworkX DiGraph construction + DOT export
    ├── reachability.py     ← Module 4: Package-aware DFS/BFS pathfinding
    ├── reporter.py         ← Module 5: Interactive HTML report generator
    └── report_template.html← Self-contained HTML template with D3.js graph

vuln_app/                   ← Intentionally vulnerable scan target
├── requirements.txt        ← Pinned to vulnerable versions
├── app.py                  ← Main entry point (orchestrates all modules)
├── config.py               ← yaml.load() without SafeLoader  [CVE-2020-14343]
├── image_handler.py        ← Image.open() no bomb check       [CVE-2022-22817]
├── web_utils.py            ← requests + Jinja2 Environment    [CVE-2023-32681, CVE-2024-34064]
└── data_processor.py       ← numpy.load allow_pickle=True     [CVE-2021-41496]
```

---

## Expected Demo Results (offline mode)

| CVE | Package | Severity | CVSS | Sink | Status |
|-----|---------|----------|------|------|--------|
| CVE-2020-14343 | PyYAML | CRITICAL | 9.8 | `yaml.load` | 🔴 **REACHABLE** — `main → run_pipeline → load_config → yaml.load` |
| CVE-2022-22817 | Pillow | HIGH | 7.5 | `Image.open` | 🔴 **REACHABLE** — `main → run_pipeline → process_image → Image.open` |
| CVE-2024-34064 | Jinja2 | MEDIUM | 5.4 | `Environment` | 🔴 **REACHABLE** — `main → run_pipeline → render_dashboard → Environment` |
| CVE-2023-32681 | requests | MEDIUM | 6.1 | `requests.get` | 🔴 **REACHABLE** — `main → run_pipeline → fetch_data → requests.get` |
| CVE-2021-41496 | numpy | HIGH | 7.8 | `numpy.load` | ✅ **UNREACHABLE** — `batch_process` never called from `main` |

Traditional SCA would flag all 5. **ReachScan suppresses the numpy false positive → 20% alert reduction.**

---

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
┌─────────────────┐     OSV.dev API
│  Module 1       │◄────────────────
│  Ingestion      │  CVE list + CVSS + fix versions
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Module 2       │  .py files → AST
│  AST Parser     │  FunctionNode, CallEdge, decorators
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Module 3       │  DiGraph (filtered)
│  Call Graph     │  nodes=functions, edges=calls, stats
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Module 4       │  Package-aware sink matching
│  Reachability   │  Score-based: entry_point → sink?
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Module 5       │  Interactive HTML + JSON
│  Reporter       │  D3.js graph · search · filter
└─────────────────┘
```

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
