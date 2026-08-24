"""The flagship check: the shipped fixture reproduces the shipped expectation.

Every number the README states about xz is recomputed here from the fixture,
offline, and compared field-for-field — plus the COUNTS.json single-source
pins and a wall-clock bound that keeps the demo instant.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import time
from pathlib import Path

from campanile.cli import FIXTURES, _fixture_lines, _xz_measure
from campanile.replay import replay_from_lines

ROOT = Path(__file__).resolve().parents[1]
FX = FIXTURES / "xz"


def _run():
    return _xz_measure(lambda cb: replay_from_lines(
        _fixture_lines(FX / "structural.log.gz"), cb, structural_only=True))


def test_fixture_reproduces_expected_exactly():
    t0 = time.monotonic()
    got = _run()
    dt = time.monotonic() - t0
    expected = json.loads((FX / "expected.json").read_text(encoding="utf-8"))
    assert got == expected
    assert dt < 120, f"replay took {dt:.1f}s — the demo must stay instant"


def test_counts_json_is_the_single_source():
    counts = json.loads((ROOT / "COUNTS.json").read_text(encoding="utf-8"))
    expected = json.loads((FX / "expected.json").read_text(encoding="utf-8"))
    man = json.loads((FX / "FIXTURE_MANIFEST.json").read_text(encoding="utf-8"))
    assert counts["n_commits"] == expected["n_commits"]
    assert counts["tests_inversion_index"] == \
        expected["m3"]["inversion_by_class"]["tests"]
    assert counts["disclosure_chain_index"] == \
        expected["disclosure_chain_index"]
    assert counts["inversion_overall"] is None
    assert counts["pin"] == expected["pin"] == man["pin"]
    assert counts["fixture_gz_sha256"] == man["gz_sha256"]
    assert counts["fixture_structural_sha256"] == man["structural_sha256"]


def test_fixture_pins_hold():
    man = json.loads((FX / "FIXTURE_MANIFEST.json").read_text(encoding="utf-8"))
    gz = FX / "structural.log.gz"
    assert hashlib.sha256(gz.read_bytes()).hexdigest() == man["gz_sha256"]
    h = hashlib.sha256()
    n = 0
    with gzip.open(gz, "rb") as fh:
        for raw in fh:
            h.update(raw)
            n += 1
    assert h.hexdigest() == man["structural_sha256"]
    assert n == man["n_lines_structural"]


def test_the_finding_reads_off_the_result():
    got = _run()
    inv = got["m3"]["inversion_by_class"]
    assert inv["tests"] == 1746
    assert inv["translations"] == 2277
    assert all(v is None for k, v in inv.items()
               if k not in ("tests", "translations"))
    assert got["m3"]["inversion_overall"] is None
    assert got["disclosure_chain_index"] == 2315
    assert got["m3"]["principals"]["incumbent"] == "Lasse Collin"
    assert got["m3"]["principals"]["challenger"] == "Jia Tan"
