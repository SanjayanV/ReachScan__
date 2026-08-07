"""Lightweight logging setup.

Levels supported: DEBUG, INFO, WARNING, ERROR. INFO is the default and is
deliberately terse — one line per phase rather than per-item chatter. The
console output intentionally mirrors the old banner style without a logging
framework dependency.
"""

from __future__ import annotations

import logging
import sys

from config import Settings, load_settings

_LOGGER_NAME = "reachscan"


def configure_logging(settings: Settings | None = None,
                      level: str | None = None) -> None:
    """Configure the root ReachScan logger.

    ``level`` overrides ``settings.logging.level`` when given (used by the
    CLI's ``--verbose`` flag). Existing handlers are replaced so that tests
    and repeated calls converge on one configuration.
    """
    settings = settings or load_settings()
    log_level = (level or settings.logging.level).upper()

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(log_level)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(settings.logging.format))
    logger.addHandler(handler)
    logger.propagate = False


def get_logger(name: str = "") -> logging.Logger:
    """Return a child logger of the ReachScan hierarchy."""
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)