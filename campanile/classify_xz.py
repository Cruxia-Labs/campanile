"""The xz file classes, frozen with the calibration case — first-match order.

These patterns ARE the calibration method's patterns; changing one breaks
the replay's argument. Generic scans never use this map (classify_generic).
"""

from __future__ import annotations

CLASSES = ("tests", "build", "translations", "docs", "source", "other")

_BUILD_PREFIXES = ("m4/", "cmake/", "build-aux/", ".github/", "ci/")
_BUILD_BASENAMES = {"CMakeLists.txt", "Makefile.am", "configure.ac", "autogen.sh"}
_BUILD_SUFFIXES = (".m4", ".am", ".ac")
_DOCS_BASENAMES = {"NEWS", "AUTHORS", "THANKS", "TODO", "ChangeLog", "INSTALL", "COPYING"}
_SOURCE_PREFIXES = ("src/", "lib/", "debug/")


def classify(path: str) -> str:
    if path.startswith("tests/"):
        return "tests"
    base = path.rsplit("/", 1)[-1]
    if (
        path.startswith(_BUILD_PREFIXES)
        or base in _BUILD_BASENAMES
        or path.endswith(_BUILD_SUFFIXES)
    ):
        return "build"
    if path.startswith(("po/", "po4a/")):
        return "translations"
    if (
        path.startswith("doc/")
        or base.startswith("README")
        or base in _DOCS_BASENAMES
        or base.startswith("COPYING.")
    ):
        return "docs"
    if path.startswith(_SOURCE_PREFIXES):
        return "source"
    return "other"
