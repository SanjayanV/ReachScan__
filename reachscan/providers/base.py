"""Vulnerability provider interface.

A provider answers, for a given dependency, the set of known
``Vulnerability`` records. Only OSV ships today; a mock backs offline/demo
mode. Future sources (NVD, GHSA) implement this small interface and register
in ``config.ProviderSettings`` without scanner-engine changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from utils.exceptions import ProviderError
from models.dependency import Vulnerability


class ProviderNotFoundError(ProviderError):
    """A requested provider name is not registered."""


class VulnerabilityProvider(ABC):
    """Contract implemented by any data source."""

    #: Human-readable identifier used to select the provider.
    name: str = "abstract"

    #: Package ecosystem this provider understands (e.g. "PyPI").
    ecosystem: str = ""

    @abstractmethod
    def lookup(self, package: str, version: str) -> list[Vulnerability]:
        """Return known vulnerabilities for ``package`` at ``version``.

        A caller may treat an empty list as "no known vulnerabilities". A
        provider should raise ``ProviderUnavailableError`` only when the
        request could not be completed at all, so the caller can decide
        whether to abort or degrade.
        """


def get_provider(name: str, settings=None, **kwargs) -> VulnerabilityProvider:
    """Instantiate a provider by name.

    Kept here (rather than in the CLI) so orchestration and tests share the
    same registry. Built-in names are mapped lazily to avoid import cycles.
    """
    from config import load_settings
    from providers.osv import OsvProvider
    from providers.mock import MockProvider

    settings = settings or load_settings()
    providers = {
        "osv": lambda: OsvProvider(
            endpoint=settings.osv.endpoint,
            ecosystem=settings.osv.ecosystem,
            request_timeout=settings.osv.request_timeout,
            max_retries=settings.osv.max_retries,
            retry_backoff=settings.osv.retry_backoff,
            **kwargs,
        ),
        "mock": lambda: MockProvider(),
    }

    factory = providers.get(name)
    if factory is None:
        raise ProviderNotFoundError(name)
    return factory()