"""Severity and scoring logic."""

from core.scoring.severity import (
    SEVERITY_ORDER,
    extract_severity,
    parse_cvss_score,
    score_to_severity,
)

__all__ = ["SEVERITY_ORDER", "extract_severity", "parse_cvss_score", "score_to_severity"]