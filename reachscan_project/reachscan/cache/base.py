"""Cache storage interface.

A cache stores serializable values keyed by string. The key space is
namespaced by the caller (e.g. ``"osv:Pillow==9.0.0"``). Implementations are
expected to surface no exceptions on read-misses — a cache that breaks the
scan is worse than no cache at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class CacheMiss(Exception):
    """Raised internally to signal a value is not present."""


class Cache(ABC):
    """Contract implemented by any cache backend."""

    @abstractmethod
    def get(self, key: str) -> object:
        """Return the cached value or raise :class:`CacheMiss`."""

    @abstractmethod
    def set(self, key: str, value: object, ttl_seconds: int | None = None) -> None:
        """Store ``value`` under ``key`` with an optional TTL."""

    @abstractmethod
    def contains(self, key: str) -> bool:
        """Whether a live value exists for ``key``."""

    @abstractmethod
    def clear(self) -> None:
        """Remove every value in the cache."""