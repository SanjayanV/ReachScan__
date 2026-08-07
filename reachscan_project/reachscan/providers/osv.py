"""OSV.dev vulnerability provider.

Queries the OSV API for the package/version pairs parsed from manifests and
transforms the JSON responses into ``Vulnerability`` records. Network access
is isolated behind ``_http_post`` so tests can substitute a fake transport.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Callable

from utils.logging import get_logger
from utils.exceptions import ProviderUnavailableError
from core.resolver.sinks import get_vulnerable_functions
from core.scoring.severity import extract_severity
from models.dependency import Vulnerability
from providers.base import VulnerabilityProvider

log = get_logger(__name__)

# HTTP statuses worth retrying with backoff.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503})


class OsvProvider(VulnerabilityProvider):
    """Queries OSV.dev for known package vulnerabilities."""

    name = "osv"
    ecosystem = "PyPI"

    def __init__(self, endpoint: str, ecosystem: str = "PyPI",
                 request_timeout: float = 15.0, max_retries: int = 3,
                 retry_backoff: float = 1.5,
                 http_post: Callable | None = None):
        self.endpoint = endpoint
        self.ecosystem = ecosystem
        self.request_timeout = request_timeout
        self.max_retries = max(1, max_retries)
        self.retry_backoff = retry_backoff
        self._http_post = http_post or self._default_post

    # -- VulnerabilityProvider -------------------------------------------------

    def lookup(self, package: str, version: str) -> list[Vulnerability]:
        """Return vulnerabilities for ``package`` at ``version``."""
        raw_entries = self._query(package, version)
        return [self._to_vulnerability(package, version, entry)
                for entry in raw_entries]

    # -- network ----------------------------------------------------------------

    def _query(self, package_name: str, version: str) -> list[dict]:
        payload = json.dumps({
            "package": {"name": package_name, "ecosystem": self.ecosystem},
            "version": version if version != "*" else None,
        }).encode("utf-8")

        for attempt in range(self.max_retries):
            try:
                body = self._http_post(self.endpoint, payload)
            except ProviderUnavailableError:
                # Backoff applies to HTTPError and URLError alike.
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff * (2 ** attempt))
                    continue
                log.error("OSV query failed for %s after %d attempt(s)",
                          package_name, self.max_retries)
                return []

            data = json.loads(body.decode("utf-8"))
            return data.get("vulns", [])

        return []

    def _default_post(self, endpoint: str, payload: bytes) -> bytes:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        for attempt in range(self.max_retries):
            try:
                with urllib.request.urlopen(req, timeout=self.request_timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                if exc.code in _RETRYABLE_STATUS and attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff * (2 ** attempt))
                    continue
                raise ProviderUnavailableError(
                    f"OSV returned HTTP {exc.code} for {endpoint}"
                ) from exc
            except urllib.error.URLError as exc:
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_backoff)
                    continue
                raise ProviderUnavailableError(
                    f"OSV request failed for {endpoint}: {exc.reason}"
                ) from exc

        raise ProviderUnavailableError(f"OSV request failed for {endpoint}")

    # -- OSV entry -> Vulnerability ----------------------------------------------

    def _to_vulnerability(self, package: str, version: str,
                          entry: dict) -> Vulnerability:
        severity, cvss_score, cvss_vector = extract_severity(entry)
        detail_text = f"{entry.get('details', '')} {entry.get('summary', '')}"

        return Vulnerability(
            cve_id=self._extract_cve_id(entry),
            package=package,
            severity=severity,
            summary=entry.get("summary", "No summary available")[:250],
            affected_versions=[version],
            vulnerable_functions=get_vulnerable_functions(package, detail_text),
            osv_id=entry.get("id", ""),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            fixed_version=self._extract_fixed_version(entry),
            references=self._extract_references(entry),
        )

    @staticmethod
    def _extract_cve_id(entry: dict) -> str:
        for alias in entry.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return entry.get("id", "UNKNOWN")

    @staticmethod
    def _extract_fixed_version(entry: dict) -> str:
        for affected in entry.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return ""

    @staticmethod
    def _extract_references(entry: dict) -> list[str]:
        refs = [ref.get("url", "") for ref in entry.get("references", [])]
        return [url for url in refs if url][:5]