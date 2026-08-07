"""Severity ordering and CVSS parsing/classification."""

from __future__ import annotations

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4,
}

_APPROX_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}


def parse_cvss_score(score_value) -> float:
    """Best-effort parse of a CVSS score.

    Accepts either a bare numeric string or a full CVSS vector, returning
    the numeric score from the last valid 0..10 token.
    """
    if not score_value:
        return 0.0

    try:
        return float(score_value)
    except (ValueError, TypeError):
        pass

    best = 0.0
    for part in str(score_value).split("/"):
        try:
            score = float(part)
            if 0.0 <= score <= 10.0:
                best = score
        except ValueError:
            continue
    return best


def score_to_severity(score: float) -> str:
    """Map a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def extract_severity(osv_entry: dict) -> tuple[str, float, str]:
    """Derive (severity, cvss_score, cvss_vector) from an OSV entry."""
    best_score = 0.0
    best_vector = ""

    for sev in osv_entry.get("severity", []):
        score = parse_cvss_score(sev.get("score", ""))
        if score > best_score:
            best_score = score
            best_vector = sev.get("score", "")

    db_specific = osv_entry.get("database_specific", {})
    if "severity" in db_specific:
        sev_str = db_specific["severity"].upper()
        if sev_str in _APPROX_SCORE:
            if best_score == 0.0:
                return sev_str, _APPROX_SCORE[sev_str], best_vector

    if best_score > 0.0:
        return score_to_severity(best_score), best_score, best_vector

    for alias in osv_entry.get("aliases", []):
        if alias.startswith("CVE"):
            return "HIGH", 7.0, ""

    return "UNKNOWN", 0.0, ""