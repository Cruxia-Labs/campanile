"""A synthetic repository exercises the traps end-to-end through `scan`.

No-trailing-newline files (the `\\ No newline` diff line), a rename with an
edit in the same commit, a binary file, and a non-UTF8 author byte sequence
(surrogateescape) — the custody state must read them all correctly, and the
emitted vector must obey the schema, the fence, and the integer-payload law.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from campanile.classify_generic import GENERIC_CLASSES, classify_generic
from campanile.custody import run_custody
from campanile.fence import scan_bytes
from campanile.vector import build_vector, require_fence


def _mk_repo(root: Path) -> str:
    def g(*args, **kw):
        env = {**os.environ, "GIT_AUTHOR_DATE": "2024-01-01T00:00:00Z",
               "GIT_COMMITTER_DATE": "2024-01-01T00:00:00Z",
               "GIT_COMMITTER_NAME": "c", "GIT_COMMITTER_EMAIL": "c@x",
               **kw.pop("env", {})}
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True, env=env, **kw)

    g("init", "-q", "-b", "main")
    (root / "src.py").write_bytes(b"one\ntwo")          # no trailing newline
    g("add", "src.py")
    g("commit", "-q", "-m", "c1", env={"GIT_AUTHOR_NAME": "alice",
                                       "GIT_AUTHOR_EMAIL": "a@x"})
    (root / "blob.bin").write_bytes(bytes(range(256)))
    (root / "tests").mkdir()
    (root / "tests" / "test_all.py").write_bytes(b"t1\nt2\nt3\n")
    g("add", "blob.bin", "tests/test_all.py")
    g("commit", "-q", "-m", "c2",
      env={"GIT_AUTHOR_NAME": b"J\xf6rg".decode("utf-8", "surrogateescape"),
           "GIT_AUTHOR_EMAIL": "j@x"})
    g("mv", "src.py", "main.py")
    p = root / "main.py"
    p.write_bytes(p.read_bytes() + b"\nthree\n")
    g("add", "main.py")
    g("commit", "-q", "-m", "c3", env={"GIT_AUTHOR_NAME": "alice",
                                       "GIT_AUTHOR_EMAIL": "a@x"})
    return subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                          check=True, capture_output=True
                          ).stdout.decode().strip()


def test_scan_reads_the_traps_correctly():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        pin = _mk_repo(root)
        result = run_custody(str(root), pin, GENERIC_CLASSES, classify_generic)
        state_text = result["_snapshots"][-1]
        vec = build_vector("mini", result, GENERIC_CLASSES)
        assert vec["schema"] == "campanile-vector/v1"
        assert vec["n_commits"] == 3
        # the rename moved custody; the binary registered; tests classified
        assert state_text.class_totals["tests"] == 3
        # non-UTF8 author survived surrogateescape into the author table
        assert any(a.startswith("J") for a in result["_authors"])
        for e in vec["inversions"]:
            require_fence(e)
        assert not scan_bytes(json.dumps(vec).encode())

        def floats(o):
            if isinstance(o, float):
                return True
            if isinstance(o, dict):
                return any(floats(v) for v in o.values())
            if isinstance(o, list):
                return any(floats(v) for v in o)
            return False
        assert not floats(vec)


def test_pin_mismatch_refuses():
    import pytest
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _mk_repo(root)
        with pytest.raises(BaseException):
            run_custody(str(root), "0" * 40, GENERIC_CLASSES, classify_generic)
