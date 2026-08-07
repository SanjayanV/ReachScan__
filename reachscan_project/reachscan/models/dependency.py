"""Models describing dependencies and their known vulnerabilities."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    """A single known vulnerability in a pinned dependency."""

    cve_id: str
    package: str
    severity: str
    summary: str
    affected_versions: list[str]
    vulnerable_functions: list[str]
    osv_id: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "package": self.package,
            "severity": self.severity,
            "summary": self.summary,
            "affected_versions": self.affected_versions,
            "vulnerable_functions": self.vulnerable_functions,
            "osv_id": self.osv_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "fixed_version": self.fixed_version,
            "references": self.references,
        }


@dataclass
class Dependency:
    """A pinned package extracted from a dependency manifest."""

    name: str
    version: str
    source_file: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)