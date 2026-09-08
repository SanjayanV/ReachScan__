"""Vulnerability providers (OSV today, NVD/GHSA later)."""

from providers.base import (
    VulnerabilityProvider,
    ProviderNotFoundError,
    get_provider,
)
from providers.manifest import (
    discover_manifests,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements,
)
from providers.mock import MockProvider
from providers.osv import OsvProvider

__all__ = [
    "VulnerabilityProvider", "ProviderNotFoundError", "get_provider",
    "discover_manifests", "parse_pipfile", "parse_pyproject_toml", "parse_requirements",
    "MockProvider", "OsvProvider",
]