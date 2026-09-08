"""Response cache (interface + manager).

Caching is *designed but not enabled*. This directory defines where cache
artefacts live, the provider-agnostic interface, and a no-op default manager
so that enabling caching later touches no scanner logic.
"""

from cache.base import Cache, CacheMiss
from cache.manager import CacheManager, get_cache_manager

__all__ = ["Cache", "CacheMiss", "CacheManager", "get_cache_manager"]