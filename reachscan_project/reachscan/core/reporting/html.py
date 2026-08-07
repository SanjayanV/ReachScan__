"""Serialise analysis results to a self-contained HTML report."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from utils.logging import get_logger
from utils.exceptions import ReportError
from core.graph.exporter import export_graph_summary
from core.reporting.base import Reporter
from core.scoring.severity import SEVERITY_ORDER
from models.graph import CallGraph
from models.result import ReachabilityResult

log = get_logger(__name__)

SEV_CLASS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
             "LOW": "low", "UNKNOWN": "unknown"}

_TEMPLATE_PATH = Path(__file__).parent / "report_template.html"


class HtmlReporter(Reporter):
    """Renders the interactive HTML security report."""

    def _sev_cls(self, sev: str) -> str:
        return SEV_CLASS.get(sev, "unknown")

    def _path_html(self, path: list) -> str:
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

    def _build_card(self, r: ReachabilityResult) -> str:
        v = r.vulnerability
        sc = self._sev_cls(v.severity)
        status_cls = "reachable" if r.is_reachable else "unreachable"
        status_lbl = "REACHABLE" if r.is_reachable else "UNREACHABLE"
        status_badge_cls = "status-reach" if r.is_reachable else "status-unreach"
        pri_cls = self._sev_cls(r.priority)

        sinks_html = "".join(f"<code>{s}</code>" for s in v.vulnerable_functions[:4])

        if r.execution_paths:
            path_rows = "".join(
                f'<div class="path-row">{self._path_html(p)}</div>'
                for p in r.execution_paths[:3]
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
            fix_html = (
                f'<div class="fix-hint">💡 Fix: Upgrade to '
                f'<strong>{v.package} ≥ {v.fixed_version}</strong></div>'
            )

        refs_html = ""
        if v.references:
            ref_links = " · ".join(
                f'<a href="{ref}" target="_blank" class="ref-link">'
                f'{ref.split("/")[-1][:30]}</a>'
                for ref in v.references[:3]
            )
            refs_html = (
                f'<div class="detail-row"><span class="detail-label">References</span>'
                f'<span>{ref_links}</span></div>'
            )

        cvss_html = ""
        if v.cvss_score > 0:
            cvss_html = (
                f'<div class="detail-row"><span class="detail-label">CVSS Score</span>'
                f'<span class="detail-value"><code>{v.cvss_score:.1f}/10.0</code></span></div>'
            )

        conf_html = ""
        if r.match_confidence > 0:
            pct = f"{r.match_confidence:.0%}"
            conf_html = (
                f'<div class="detail-row"><span class="detail-label">Match Confidence</span>'
                f'<span class="detail-value"><code>{pct}</code></span></div>'
            )

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

    def render(self, results: list[ReachabilityResult],
               target_dir: str,
               output_path: str | None,
               call_graph: CallGraph | None) -> str:
        reachable = [r for r in results if r.is_reachable]
        unreachable = [r for r in results if not r.is_reachable]

        sorted_results = sorted(
            results,
            key=lambda r: (0 if r.is_reachable else 1,
                           SEVERITY_ORDER.get(r.vulnerability.severity, 99)),
        )

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reduction = f"{(len(unreachable)/len(results)*100):.0f}%" if results else "N/A"

        reachable_cards = "".join(self._build_card(r) for r in sorted_results if r.is_reachable)
        unreachable_cards = "".join(self._build_card(r) for r in sorted_results if not r.is_reachable)

        reach_section = (
            f'<div class="section-title">🔴 Reachable Vulnerabilities — Immediate Action Required</div>'
            f'<div class="vuln-list">{reachable_cards}</div>'
        ) if reachable else "<p class='no-vulns'>✓ No reachable vulnerabilities found.</p>"

        unreach_section = (
            f'<div class="section-title">✅ Unreachable Vulnerabilities — No Action Required</div>'
            f'<div class="vuln-list">{unreachable_cards}</div>'
        ) if unreachable else ""

        cards_html = reach_section + unreach_section

        graph_summary = (
            export_graph_summary(call_graph) if call_graph else {"nodes": [], "edges": []}
        )
        graph_json = json.dumps(graph_summary).replace("'", "\\'").replace("</", "<\\/")

        try:
            html = _TEMPLATE_PATH.read_text(encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"Could not read HTML template: {exc}") from exc

        html = (html
                .replace("{{TARGET_DIR}}", target_dir)
                .replace("{{TIMESTAMP}}", timestamp)
                .replace("{{TOTAL}}", str(len(results)))
                .replace("{{REACHABLE}}", str(len(reachable)))
                .replace("{{UNREACHABLE}}", str(len(unreachable)))
                .replace("{{REDUCTION}}", reduction)
                .replace("{{CARDS_HTML}}", cards_html)
                .replace("{{GRAPH_JSON}}", graph_json))

        out = output_path or "report.html"
        try:
            out_path = Path(out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(html, encoding="utf-8")
        except OSError as exc:
            raise ReportError(f"Could not write HTML report: {exc}") from exc

        log.info("HTML report written to %s", out)
        return str(out_path)