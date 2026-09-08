"""Cache manager: owns the cache location and lifecycle.

The manager is the single place the rest of the codebase talks to. Today it
returns a no-op / disabled cache backed by the location in the settings.
Future work can swap the backend here without touching callers.
"""

from __future__ import annotations

from config import CacheSettings, load_settings
from cache.base import Cache, CacheMiss
from utils.logging import get_logger

log = get_logger(__name__)


class NullCache(Cache):
    """A disabled cache: never stores, always misses.

    Kept deliberately trivial so that wiring caching on later is a one-line
    backend swap rather than a re-plumbing of the pipeline.
    """

    def get(self, key: str) -> object:
        raise CacheMiss(key)

    def set(self, key: str, value: object, ttl_seconds: int | None = None) -> None:
        return None

    def contains(self, key: str) -> bool:
        return False

    def clear(self) -> None:
        return None


class CacheManager:
    """Owns the live cache instance and its on-disk location."""

    def __init__(self, settings: CacheSettings | None = None):
        self.settings = settings or load_settings().cache

        if not self.settings.enabled:
            self._cache: Cache = NullCache()
        else:
            # Placeholder: instantiate a real Cache backend here once one
            # exists. Kept behind a guard so enabling it is safe.
            self._cache: Cache = NullCache()

        log.debug("Cache manager initialized (enabled=%s, dir=%s)",
                  self.settings.enabled, self.settings.dir)

    @property
    def cache(self) -> Cache:
        return self._cache

    @property
    def location(self) -> str:
        return str(self.settings.dir)


_manager: CacheManager | None = None


def get_cache_manager(settings: CacheSettings | None = None) -> CacheManager:
    """Return the process-wide cache manager (creates on first use)."""
    global _manager
    if _manager is None:
        _manager = CacheManager(settings)
    return _manager