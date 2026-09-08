"""Name and sink resolution helpers.

These modules translate package knowledge (import aliases, known sink
function signatures) and match call-graph nodes against sink signatures.
"""

from core.resolver.sinks import KNOWN_SINK_SIGNATURES, get_vulnerable_functions
from core.resolver.imports import PACKAGE_TO_IMPORT, get_import_names
from core.resolver.matching import match_score

__all__ = [
    "KNOWN_SINK_SIGNATURES", "get_vulnerable_functions",
    "PACKAGE_TO_IMPORT", "get_import_names",
    "match_score",
]