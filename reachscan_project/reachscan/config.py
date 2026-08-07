"""
Central configuration for ReachScan.

Every tunable value (network endpoints, timeouts, paths, logging, future
provider settings) lives here so that no module hardcodes a magic value.
Settings can be overridden via the ``REACHSCAN_*`` environment variables,
which is useful for CI and containerised runs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default):
    """Read an environment variable, falling back to ``default``."""
    value = os.environ.get(name)
    if value is None:
        return default
    if isinstance(default, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    return value


@dataclass(frozen=True)
class OsvSettings:
    """Network behaviour for the OSV vulnerability provider."""

    endpoint: str = "https://api.osv.dev/v1/query"
    ecosystem: str = "PyPI"
    request_timeout: float = 15.0
    max_retries: int = 3
    retry_backoff: float = 1.5


@dataclass(frozen=True)
class CacheSettings:
    """Location and behaviour of the (future) response cache."""

    dir: Path = field(default_factory=lambda: Path.home() / ".cache" / "reachscan")
    enabled: bool = False  # caching is designed but not enabled yet
    ttl_seconds: int = 86400  # 24h default expiry


@dataclass(frozen=True)
class ReportSettings:
    """Default location for generated artefacts."""

    html_output: str = "reports/report.html"
    json_output: str = ""  # empty => derived from the html output path


@dataclass(frozen=True)
class LoggingSettings:
    """Logging configuration. Logging is intentionally not very verbose."""

    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


@dataclass(frozen=True)
class ParserSettings:
    """Directories the AST parser should never descend into."""

    skip_dirs: tuple[str, ...] = (
        "__pycache__", ".git", ".hg", ".svn",
        "venv", ".venv", "node_modules",
        ".tox", ".mypy_cache", ".pytest_cache",
        "dist", "build", "egg-info", ".eggs",
    )


@dataclass(frozen=True)
class ProviderSettings:
    """
    Registry mapping a provider name to its implementation.

    Today only OSV ships with the engine; a mock provider supports offline
    demo mode. Future data sources (NVD, GHSA, ...) register here without
    touching scanner orchestration logic.
    """

    providers: tuple[str, ...] = ("osv", "mock")
    default: str = "osv"


@dataclass(frozen=True)
class Settings:
    """Aggregate of every ReachScan configuration group."""

    osv: OsvSettings = field(default_factory=OsvSettings)
    cache: CacheSettings = field(default_factory=CacheSettings)
    report: ReportSettings = field(default_factory=ReportSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    parser: ParserSettings = field(default_factory=ParserSettings)
    providers: ProviderSettings = field(default_factory=ProviderSettings)


def load_settings() -> Settings:
    """Build the settings object, honouring ``REACHSCAN_*`` overrides."""
    return Settings(
        osv=OsvSettings(
            endpoint=_env("REACHSCAN_OSV_ENDPOINT", OsvSettings().endpoint),
            request_timeout=_env("REACHSCAN_TIMEOUT", OsvSettings().request_timeout),
            max_retries=_env("REACHSCAN_RETRIES", OsvSettings().max_retries),
            retry_backoff=_env("REACHSCAN_BACKOFF", OsvSettings().retry_backoff),
        ),
        cache=CacheSettings(
            dir=Path(_env("REACHSCAN_CACHE_DIR", str(CacheSettings().dir))),
            enabled=_env("REACHSCAN_CACHE_ENABLED", CacheSettings().enabled),
        ),
        report=ReportSettings(
            html_output=_env("REACHSCAN_REPORT_OUT", ReportSettings().html_output),
        ),
        logging=LoggingSettings(
            level=_env("REACHSCAN_LOG_LEVEL", LoggingSettings().level),
        ),
    )