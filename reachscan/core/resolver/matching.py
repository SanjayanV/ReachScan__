"""Package-aware sink matching.

Given a call-graph node and a vulnerable function signature, produce a
confidence score. Matching is package-aware so that ``yaml.load`` does not
falsely match ``numpy.load``.
"""

from __future__ import annotations

from core.resolver.imports import get_import_names


def match_score(node_name: str, vulnerable_func: str, package_name: str) -> float:
    """Score how well ``node_name`` matches a vulnerable function signature.

    Returns a value in [0.0, 1.0]. Values below 0.30 are treated as
    non-matches by the reachability engine.
    """
    node_lower = node_name.lower()
    vf_lower = vulnerable_func.lower()

    import_names = get_import_names(package_name)
    import_names_lower = [n.lower() for n in import_names]

    if node_name == vulnerable_func:
        return 1.00

    if node_lower == vf_lower:
        return 0.95

    if node_lower.endswith("." + vf_lower):
        return 0.90

    vf_root = vf_lower.split(".")[0] if "." in vf_lower else ""
    node_root = node_lower.split(".")[0] if "." in node_lower else ""

    if vf_root:
        if node_root in import_names_lower or node_root == vf_root:
            vf_func = vf_lower.split(".")[-1]
            node_func = node_lower.split(".")[-1]
            if node_func == vf_func:
                return 0.80
        else:
            return 0.0

    if not vf_root:
        node_func = node_lower.split(".")[-1]
        if node_func == vf_lower:
            if node_root in import_names_lower:
                return 0.70
            if not node_root:
                return 0.30

    return 0.0