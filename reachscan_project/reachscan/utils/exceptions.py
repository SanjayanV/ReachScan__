"""ReachScan exceptions.

All expected failure modes raise a subclass of ``ReachScanError`` so callers
can catch one type and still distinguish specific conditions. Nothing is
silently swallowed: transient failures surface as warnings and the scan
continues where safe; fatal conditions raise.
"""


class ReachScanError(Exception):
    """Base class for every ReachScan error."""


class ConfigurationError(ReachScanError):
    """Invalid or unusable configuration."""


class ManifestNotFoundError(ReachScanError):
    """The dependency manifest does not exist or cannot be read."""


class ManifestParseError(ReachScanError):
    """A dependency manifest could not be parsed."""


class ProviderError(ReachScanError):
    """A vulnerability provider failed (network, malformed payload, ...)."""


class ProviderUnavailableError(ProviderError):
    """A provider could not complete a request after all retries."""


class ParseError(ReachScanError):
    """A source file could not be parsed."""


class GraphError(ReachScanError):
    """The call graph could not be constructed."""


class ReportError(ReachScanError):
    """A report could not be generated or written."""


class CacheError(ReachScanError):
    """The cache manager could not fulfil an operation."""