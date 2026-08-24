"""classify_generic — the repo-neutral file-class map.

THIS FILE IS A METHOD FILE: its sha256 is pinned by a sweep's preregistration
before any run, so the class map is declared, not tuned. First-match order,
like the frozen xz map (classify_xz.py, kept for the calibration case and
never used generically).

Classes: tests · build · docs · source · other. (xz's `translations` class is
incident-appropriate, not fleet-generic; po/ files fall to `other` here and
that choice is part of the declared method.)
"""
from __future__ import annotations

GENERIC_CLASSES = ("tests", "build", "docs", "source", "other")

_TEST_PREFIXES = ("tests/", "test/", "spec/", "__tests__/", "testing/")
_TEST_TOKENS = ("_test.", ".test.", ".spec.")
_BUILD_PREFIXES = (".github/", "ci/", ".ci/", "build/", "cmake/", "m4/",
                   "build-aux/", ".circleci/", "docker/", "deploy/")
_BUILD_BASENAMES = {
    "CMakeLists.txt", "Makefile", "Makefile.am", "makefile", "configure.ac",
    "configure", "autogen.sh", "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "requirements.txt", "tox.ini",
    "noxfile.py", ".gitignore", ".gitattributes", ".pre-commit-config.yaml",
}
_BUILD_SUFFIXES = (".yml", ".yaml", ".toml", ".ini", ".cfg", ".m4", ".am",
                   ".ac", ".mk", ".gradle", ".bazel", ".bzl")
_DOCS_PREFIXES = ("docs/", "doc/", "documentation/", "man/", "examples/")
_DOCS_BASENAMES = {"NEWS", "AUTHORS", "THANKS", "TODO", "ChangeLog",
                   "INSTALL", "COPYING", "LICENSE", "NOTICE", "CHANGELOG",
                   "CONTRIBUTING", "CODE_OF_CONDUCT"}
_DOCS_SUFFIXES = (".md", ".rst", ".txt", ".adoc", ".1", ".5", ".8")
_SOURCE_SUFFIXES = (".py", ".rs", ".go", ".c", ".h", ".cc", ".cpp", ".hpp",
                    ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".rb",
                    ".php", ".swift", ".m", ".mm", ".sh", ".pl", ".lua",
                    ".scala", ".ex", ".exs", ".erl", ".hs", ".ml", ".vue",
                    ".svelte", ".css", ".scss", ".sql", ".proto", ".zig")


def classify_generic(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    low = path.lower()
    if (low.startswith(_TEST_PREFIXES) or "/tests/" in low or "/test/" in low
            or any(t in base.lower() for t in _TEST_TOKENS)
            or base.lower().startswith("test_") or base.lower().startswith("conftest")):
        return "tests"
    if (path.startswith(_BUILD_PREFIXES) or base in _BUILD_BASENAMES
            or base.endswith(_BUILD_SUFFIXES)):
        return "build"
    if (path.startswith(_DOCS_PREFIXES) or base in _DOCS_BASENAMES
            or base.upper().startswith("README")
            or base.endswith(_DOCS_SUFFIXES)):
        return "docs"
    if base.endswith(_SOURCE_SUFFIXES):
        return "source"
    return "other"


__all__ = ["GENERIC_CLASSES", "classify_generic"]
