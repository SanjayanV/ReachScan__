"""Parsing of dependency manifest files into Dependency records.

Supports requirements.txt, Pipfile and pyproject.toml using only stdlib —
the lightweight parsing approach that keeps ReachScan dependency-free.
"""

from __future__ import annotations

import re
from pathlib import Path

from utils.logging import get_logger
from utils.exceptions import ManifestNotFoundError, ManifestParseError
from models.dependency import Dependency

log = get_logger(__name__)

_VERSION_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)")
_NAME_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)")


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ManifestParseError(f"Could not read manifest {path}: {exc}") from exc


def parse_requirements(req_file: str) -> list[Dependency]:
    """Parse a ``requirements.txt``-style manifest."""
    path = Path(req_file)
    deps: list[Dependency] = []

    if not path.exists():
        raise ManifestNotFoundError(f"Requirements file not found: {req_file}")

    for line in _read_lines(path):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = _VERSION_RE.match(line)
        if match:
            name, version = match.group(1), match.group(3)
        else:
            name_match = _NAME_RE.match(line)
            if not name_match:
                continue
            name, version = name_match.group(1), "*"

        deps.append(Dependency(name=name, version=version, source_file=str(path)))

    return deps


def parse_pipfile(pipfile_path: str) -> list[Dependency]:
    """Parse a ``Pipfile`` if present."""
    path = Path(pipfile_path)
    if not path.exists():
        return []

    deps: list[Dependency] = []
    in_packages = False

    for line in _read_lines(path):
        line = line.strip()
        if line == "[packages]":
            in_packages = True
            continue
        if line.startswith("["):
            in_packages = False
            continue

        if in_packages and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip().strip('"')
            version = parts[1].strip().strip('"').lstrip("=~><!")
            deps.append(Dependency(name=name, version=version or "*",
                                   source_file=str(path)))

    return deps


def parse_pyproject_toml(toml_path: str) -> list[Dependency]:
    """Parse a ``pyproject.toml`` dependency list if present."""
    path = Path(toml_path)
    if not path.exists():
        return []

    deps: list[Dependency] = []
    in_deps = False

    for line in _read_lines(path):
        line = line.strip()
        if line == "dependencies = [":
            in_deps = True
            continue
        if in_deps and line == "]":
            in_deps = False
            continue

        if in_deps:
            dep_str = line.strip(",").strip().strip('"').strip("'")
            match = _VERSION_RE.match(dep_str)
            if match:
                name, version = match.group(1), match.group(3)
            else:
                name_match = _NAME_RE.match(dep_str)
                name = name_match.group(1) if name_match else ""
                version = "*"
            if name:
                deps.append(Dependency(name=name, version=version,
                                       source_file=str(path)))

    return deps


def discover_manifests(directory: str, req_file: str | None = None) -> list[Dependency]:
    """Discover and parse all dependency manifests under ``directory``.

    A deduplication keeps the highest-confidence version of repeated packages
    (preferring a pinned version over ``*``). Mirrors previous behaviour.
    """
    deps: list[Dependency] = []

    if req_file:
        deps.extend(parse_requirements(req_file))
    else:
        req_path = Path(directory) / "requirements.txt"
        if req_path.exists():
            deps.extend(parse_requirements(str(req_path)))

    pipfile_path = Path(directory) / "Pipfile"
    if pipfile_path.exists():
        deps.extend(parse_pipfile(str(pipfile_path)))

    pyproject_path = Path(directory) / "pyproject.toml"
    if pyproject_path.exists():
        deps.extend(parse_pyproject_toml(str(pyproject_path)))

    if not deps:
        log.warning("No dependency manifests found under %s", directory)

    # Deduplicate by (lowercased) name, preferring a concrete version.
    best: dict[str, Dependency] = {}
    for dep in deps:
        key = dep.name.lower()
        current = best.get(key)
        if current is None:
            best[key] = dep
        elif current.version == "*" and dep.version != "*":
            best[key] = dep

    return list(best.values())