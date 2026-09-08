"""Models describing reachability analysis outcomes."""

from __future__ import annotations

from dataclasses import dataclass

from models.dependency import Vulnerability
from models.dataflow import DataflowResult


@dataclass
class ReachabilityResult:
    """Outcome of analysing whether one vulnerability is reachable."""

    vulnerability: Vulnerability
    is_reachable: bool
    reachable_via: list[str]
    execution_paths: list[list[str]]
    unreachable_sinks: list[str]
    missing_sinks: list[str]
    match_confidence: float = 0.0
    dataflow: DataflowResult | None = None

    @property
    def status(self) -> str:
        return "REACHABLE" if self.is_reachable else "UNREACHABLE"

    @property
    def priority(self) -> str:
        """Map (reachability, severity) onto a fix priority."""

        if not self.is_reachable:
            return "LOW"
        sev = self.vulnerability.severity
        if sev in ("CRITICAL", "HIGH"):
            return "CRITICAL"
        elif sev == "MEDIUM":
            return "HIGH"
        return "MEDIUM"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.vulnerability.cve_id,
            "package": self.vulnerability.package,
            "severity": self.vulnerability.severity,
            "priority": self.priority,
            "status": self.status,
            "is_reachable": self.is_reachable,
            "summary": self.vulnerability.summary,
            "vulnerable_functions": self.vulnerability.vulnerable_functions,
            "reachable_via": self.reachable_via,
            "execution_paths": self.execution_paths,
            "unreachable_sinks": self.unreachable_sinks,
            "missing_sinks": self.missing_sinks,
            "match_confidence": round(self.match_confidence, 2),
            "cvss_score": self.vulnerability.cvss_score,
            "fixed_version": self.vulnerability.fixed_version,
            "references": self.vulnerability.references,
            "dataflow": self._dataflow_dict(),
        }

    def _dataflow_dict(self) -> dict | None:
        if self.dataflow is None:
            return None
        return {
            "verdict": self.dataflow.verdict.value,
            "tainted_path_segment": self.dataflow.tainted_path_segment,
            "origin": self.dataflow.origin.value if self.dataflow.origin else None,
            "explanation": self.dataflow.explanation,
        }