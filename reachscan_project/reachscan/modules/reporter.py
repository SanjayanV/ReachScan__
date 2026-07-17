"""
Module 5: Report Generator
Generates a self-contained interactive HTML security report.
"""

import os
import json
from pathlib import Path
from datetime import datetime
from modules.reachability import ReachabilityResult
from modules.graph import CallGraph, export_graph_summary

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEV_CLASS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "UNKNOWN": "unknown"}


def _sev_cls(sev: str) -> str:
    return SEV_CLASS.get(sev, "unknown")


def _path_html(path: list) -> str:
    if not path:
        return ""
    parts = []
    for i, node in enumerate(path):
        short = node.split(".")[-1]
        cls = "entry" if i == 0 else "sink" if i == len(path) - 1 else "mid"
        parts.append(f'<span class="path-node {cls}" title="{node}">{short}</span>')
        if i < len(path) - 1:
            parts.append('<span class="path-arrow">→</span>')
    return "".join(parts)


def _build_card(r: ReachabilityResult) -> str:
    v = r.vulnerability
    sc = _sev_cls(v.severity)
    status_cls = "reachable" if r.is_reachable else "unreachable"
    status_lbl = "REACHABLE" if r.is_reachable else "UNREACHABLE"
    status_badge_cls = "status-reach" if r.is_reachable else "status-unreach"
    pri_cls = _sev_cls(r.priority)

    sinks_html = "".join(f"<code>{s}</code>" for s in v.vulnerable_functions[:4])

    if r.execution_paths:
        path_rows = "".join(
            f'<div class="path-row">{_path_html(p)}</div>' for p in r.execution_paths[:3]
        )
        paths_html = (
            f'<div class="paths-box">'
            f'<div class="paths-title">Execution Path(s)</div>'
            f'{path_rows}</div>'
        )
    elif r.unreachable_sinks:
        sinks_str = ", ".join(s.split(".")[-1] for s in r.unreachable_sinks[:3])
        paths_html = (
            f'<div class="paths-box">'
            f'<div class="paths-title">Sink Analysis</div>'
            f'Sink(s) present in graph but <strong>not reachable</strong> from any entry point: '
            f'<code>{sinks_str}</code></div>'
        )
    elif r.missing_sinks:
        sinks_str = ", ".join(r.missing_sinks[:3])
        paths_html = (
            f'<div class="paths-box">'
            f'<div class="paths-title">Sink Analysis</div>'
            f'Vulnerable functions not detected in codebase: '
            f'<code>{sinks_str}</code></div>'
        )
    else:
        paths_html = ""

    fix_html = ""
    if v.fixed_version:
        fix_html = f'<div class="fix-hint">💡 Fix: Upgrade to <strong>{v.package} ≥ {v.fixed_version}</strong></div>'

    refs_html = ""
    if v.references:
        ref_links = " · ".join(
            f'<a href="{ref}" target="_blank" class="ref-link">{ref.split("/")[-1][:30]}</a>'
            for ref in v.references[:3]
        )
        refs_html = f'<div class="detail-row"><span class="detail-label">References</span><span>{ref_links}</span></div>'

    cvss_html = ""
    if v.cvss_score > 0:
        cvss_html = f'<div class="detail-row"><span class="detail-label">CVSS Score</span><span class="detail-value"><code>{v.cvss_score:.1f}/10.0</code></span></div>'

    conf_html = ""
    if r.match_confidence > 0:
        pct = f"{r.match_confidence:.0%}"
        conf_html = f'<div class="detail-row"><span class="detail-label">Match Confidence</span><span class="detail-value"><code>{pct}</code></span></div>'

    return f"""
    <div class="vuln-card {status_cls}" data-severity="{sc}" data-status="{status_cls}">
      <div class="card-header">
        <div class="card-left">
          <span class="cve-badge">{v.cve_id}</span>
          <span class="package-name">{v.package}</span>
        </div>
        <div class="card-right">
          <span class="badge sev-{sc}">{v.severity}</span>
          <span class="badge {status_badge_cls}">{status_lbl}</span>
          <span class="badge sev-{pri_cls}">Priority: {r.priority}</span>
          <span class="expand-icon">▼</span>
        </div>
      </div>
      <div class="card-body">
        <div class="card-body-inner">
          <p class="summary">{v.summary}</p>
          <div class="detail-row">
            <span class="detail-label">Vuln Functions</span>
            <span class="detail-value">{sinks_html}</span>
          </div>
          {cvss_html}
          {conf_html}
          {refs_html}
          {paths_html}
          {fix_html}
        </div>
      </div>
    </div>"""


def generate_html_report(results: list[ReachabilityResult],
                         target_dir: str,
                         output_path: str,
                         call_graph: CallGraph = None) -> str:
    reachable = [r for r in results if r.is_reachable]
    unreachable = [r for r in results if not r.is_reachable]

    sorted_results = sorted(
        results,
        key=lambda r: (0 if r.is_reachable else 1,
                       SEVERITY_ORDER.get(r.vulnerability.severity, 99))
    )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reduction = f"{(len(unreachable)/len(results)*100):.0f}%" if results else "N/A"

    reachable_cards = "".join(_build_card(r) for r in sorted_results if r.is_reachable)
    unreachable_cards = "".join(_build_card(r) for r in sorted_results if not r.is_reachable)

    reach_section = (
        f'<div class="section-title">🔴 Reachable Vulnerabilities — Immediate Action Required</div>'
        f'<div class="vuln-list">{reachable_cards}</div>'
    ) if reachable else "<p class='no-vulns'>✓ No reachable vulnerabilities found.</p>"

    unreach_section = (
        f'<div class="section-title">✅ Unreachable Vulnerabilities — No Action Required</div>'
        f'<div class="vuln-list">{unreachable_cards}</div>'
    ) if unreachable else ""

    cards_html = reach_section + unreach_section

    if call_graph:
        graph_summary = export_graph_summary(call_graph)
    else:
        graph_summary = {"nodes": [], "edges": []}

    graph_json = json.dumps(graph_summary).replace("'", "\\'").replace("</", "<\\/")

    template_path = Path(__file__).parent / "report_template.html"
    with open(template_path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("{{TARGET_DIR}}", target_dir)
    html = html.replace("{{TIMESTAMP}}", timestamp)
    html = html.replace("{{TOTAL}}", str(len(results)))
    html = html.replace("{{REACHABLE}}", str(len(reachable)))
    html = html.replace("{{UNREACHABLE}}", str(len(unreachable)))
    html = html.replace("{{REDUCTION}}", reduction)
    html = html.replace("{{CARDS_HTML}}", cards_html)
    html = html.replace("{{GRAPH_JSON}}", graph_json)

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
