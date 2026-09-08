"""Mapping distribution names to the import names used in source."""

from __future__ import annotations


# Distribution name -> the import modules by which it usually appears in code.
PACKAGE_TO_IMPORT: dict[str, list[str]] = {
    "pyyaml":       ["yaml"],
    "pillow":       ["PIL", "Image"],
    "scikit-learn": ["sklearn"],
    "beautifulsoup4": ["bs4"],
    "python-dateutil": ["dateutil"],
    "opencv-python": ["cv2"],
    "pycryptodome": ["Crypto"],
}


def get_import_names(package_name: str) -> list[str]:
    """Return the plausible import names for a distribution name."""
    names: list[str] = []
    pkg_lower = package_name.lower()
    if pkg_lower in PACKAGE_TO_IMPORT:
        names.extend(PACKAGE_TO_IMPORT[pkg_lower])

    names.extend([
        package_name,
        package_name.lower(),
        package_name.replace("-", "_"),
        package_name.replace("-", "_").lower(),
    ])

    return list(set(names))