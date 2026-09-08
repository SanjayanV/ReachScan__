"""Mock vulnerability provider for offline / demo mode.

Reproduces the fixed set of demo CVEs that the client previously returned.
The mock is intentionally deterministic so the pipeline behaves identically
on every run without network access.
"""

from __future__ import annotations

from models.dependency import Vulnerability
from providers.base import VulnerabilityProvider


class MockProvider(VulnerabilityProvider):
    """Returns a fixed demo CVE set for any dependency."""

    name = "mock"
    ecosystem = "demo"

    def __init__(self):
        self._vulns = _build_demo_vulns()

    def lookup(self, package: str, version: str) -> list[Vulnerability]:
        """Return the demo set, mirroring the previous offline behaviour."""
        return list(self._vulns)


def _build_demo_vulns() -> list[Vulnerability]:
    return [
        Vulnerability(
            cve_id="CVE-2020-14343", package="PyYAML", severity="CRITICAL",
            summary="PyYAML yaml.load() without Loader is susceptible to arbitrary code execution via a crafted YAML payload.",
            affected_versions=["5.3.1"],
            vulnerable_functions=["yaml.load", "yaml.unsafe_load"],
            osv_id="GHSA-8q59-q68h-6hv4",
            cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            fixed_version="5.4",
            references=["https://github.com/yaml/pyyaml/issues/420"],
        ),
        Vulnerability(
            cve_id="CVE-2022-22817", package="Pillow", severity="HIGH",
            summary="Pillow PIL.Image.open is vulnerable to a decompression bomb attack leading to denial of service.",
            affected_versions=["9.0.0"],
            vulnerable_functions=["Image.open", "Image.frombuffer"],
            osv_id="GHSA-4fx9-hhprp-fxc3",
            cvss_score=7.5, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            fixed_version="9.0.1",
            references=["https://pillow.readthedocs.io/en/stable/releasenotes/9.0.1.html"],
        ),
        Vulnerability(
            cve_id="CVE-2024-34064", package="Jinja2", severity="MEDIUM",
            summary="Jinja2 Template rendering is vulnerable to XSS via the xmlattr filter when keys contain certain characters.",
            affected_versions=["3.0.0"],
            vulnerable_functions=["Template", "Environment"],
            osv_id="GHSA-h75v-3vvj-5mfj",
            cvss_score=5.4, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            fixed_version="3.1.4",
            references=["https://github.com/pallets/jinja/security/advisories/GHSA-h75v-3vvj-5mfj"],
        ),
        Vulnerability(
            cve_id="CVE-2023-32681", package="requests", severity="MEDIUM",
            summary="Requests library forwards proxy-authorization headers to destination servers, leaking credentials.",
            affected_versions=["2.28.0"],
            vulnerable_functions=["requests.get", "requests.post", "requests.Session"],
            osv_id="GHSA-j8r2-6x86-q33q",
            cvss_score=6.1, cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
            fixed_version="2.31.0",
            references=["https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"],
        ),
        Vulnerability(
            cve_id="CVE-2021-41496", package="numpy", severity="HIGH",
            summary="NumPy numpy.load with allow_pickle=True is vulnerable to arbitrary code execution through crafted .npy files.",
            affected_versions=["1.21.0"],
            vulnerable_functions=["numpy.load", "numpy.fromstring"],
            osv_id="GHSA-fpfv-jqm9-f5jm",
            cvss_score=7.8, cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            fixed_version="1.22.0",
            references=["https://github.com/numpy/numpy/issues/19000"],
        ),
    ]