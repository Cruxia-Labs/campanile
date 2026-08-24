"""The commands a stranger actually types, run end-to-end as subprocesses."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(*args):
    return subprocess.run([sys.executable, "-m", "campanile", *args],
                          capture_output=True, text=True, cwd=ROOT)


def test_replay_xz_exits_green():
    r = _run("replay", "xz")
    assert r.returncode == 0, r.stderr
    assert "replay: GREEN" in r.stdout
    assert "1746" in r.stdout and "2023-03-13" in r.stdout


def test_unknown_case_refuses():
    r = _run("replay", "left-pad")
    assert r.returncode == 2


def test_verify_dispatches_on_the_fixture_manifest():
    man = ROOT / "campanile" / "fixtures" / "xz" / "FIXTURE_MANIFEST.json"
    r = _run("verify", str(man))
    assert r.returncode == 0, r.stderr
    assert "pins hold" in r.stdout
