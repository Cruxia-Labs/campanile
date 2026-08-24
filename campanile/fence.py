"""fence — accusation vocabulary is BANNED from campanile outputs.

The instrument reports STRUCTURE (custody shares, inversion dates); the moment
an output word implies wrongdoing, the fence has failed regardless of schema.
Case-insensitive substring scan over artifact bytes; the scan runs on every
vector, every sealed artifact, and this package's own emitted text.
"""
from __future__ import annotations

import sys
from pathlib import Path

BANNED = ("attacker", "compromise", "malicious", "backdoor", "infiltrat",
          "suspect", "culprit", "perpetrator")


def scan_bytes(data: bytes, where: str = "artifact") -> list:
    """The one exemption: the canonical fence disclaimer NAMES what it denies
    ("not a compromise indicator") — the first fleet run flagged its own fence
    sentence one repo in. Exact canonical strings are removed before the scan;
    any OTHER occurrence still fires."""
    from campanile.vector import WHAT_THIS_IS, WHAT_THIS_IS_NOT
    text = data.decode("utf-8", errors="replace")
    for canon in (WHAT_THIS_IS_NOT, WHAT_THIS_IS):
        text = text.replace(canon, "")
    low = text.lower()
    return [w for w in BANNED if w in low]


def scan_paths(paths) -> int:
    bad = 0
    for p in paths:
        hits = scan_bytes(Path(p).read_bytes(), str(p))
        if hits:
            print(f"FENCE LEXICON RED: {p} contains {hits}", file=sys.stderr)
            bad += 1
    return bad


if __name__ == "__main__":
    raise SystemExit(1 if scan_paths(sys.argv[1:]) else 0)
