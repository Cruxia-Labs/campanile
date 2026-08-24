"""custody — the frozen physics, re-hosted with a pluggable classifier.

The replay (replay.py — vendored from the frozen upstream physics with one
seam, see its docstring) attributes every surviving line; this module folds
the replay into measures. Three things that were constants upstream are
arguments here:

  - `classes` + `classify_fn` — the xz map (classify_xz.py) stays frozen for
    the calibration case; generic scans use classify_generic;
  - `OverlaySpec` — the hindsight overlay is per-incident only, never
    fleet-wide (xz's lives in xz_constants.py);
  - `disclosure_date` — optional; None skips the disclosure index.

DRIFT FENCE: exact xz parity through this path against the shipped
expectation (tests/test_replay_xz.py) — a re-host that drifts fails loudly
on the recorded numbers, not silently.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date as _date
from typing import Callable, List, Optional

from campanile.replay import Commit, CustodyState, replay

AUTHOR_FILTER_PEAK_SHARE = 0.01


@dataclass(frozen=True)
class OverlaySpec:
    """Per-incident hindsight overlay (xz's M7 shape). Never fleet-wide."""
    paths: tuple
    window: tuple            # (start_day, end_day) — [start, end)
    tarball_only_path: str = ""


@dataclass
class _FileEntry:
    cls: str
    counter: dict = field(default_factory=dict)
    total: int = 0
    is_binary: bool = False
    owner: int = -1
    multi: bool = False


@dataclass
class Snapshot:
    sha: str
    date: str
    author: str
    class_totals: dict
    class_author: dict
    overall: dict
    sole_lines: dict
    sole_files: dict
    multi_lines: dict
    binary_counts: dict


class GenericMeasureBuilder:
    """MeasureBuilder with the xz constants factored into arguments."""

    def __init__(self, classes: tuple, classify_fn: Callable[[str], str],
                 overlay: Optional[OverlaySpec] = None) -> None:
        self.classes = classes
        self.classify = classify_fn
        self.overlay = overlay
        self.cache: dict = {}
        self.class_totals = {c: 0 for c in classes}
        self.class_author = {c: {} for c in classes}
        self.overall: dict = {}
        self.sole_lines = {c: 0 for c in classes}
        self.sole_files = {c: 0 for c in classes}
        self.multi_lines: dict = {}
        self.binary_counts = {c: {} for c in classes}
        self.snapshots: List[Snapshot] = []
        self.overlay_events: List[dict] = []
        self.tarball_only_seen = False

    def _bump(self, d: dict, aid: int, n: int) -> None:
        v = d.get(aid, 0) + n
        if v:
            d[aid] = v
        else:
            d.pop(aid, None)

    def _remove(self, e: _FileEntry) -> None:
        if e.is_binary:
            self._bump(self.binary_counts[e.cls], e.owner, -1)
            return
        self.class_totals[e.cls] -= e.total
        for aid, n in e.counter.items():
            self._bump(self.class_author[e.cls], aid, -n)
            self._bump(self.overall, aid, -n)
            if e.multi:
                self._bump(self.multi_lines, aid, -n)
        if len(e.counter) == 1 and e.total > 0:
            self.sole_lines[e.cls] -= e.total
            self.sole_files[e.cls] -= 1

    def _add(self, e: _FileEntry) -> None:
        if e.is_binary:
            self._bump(self.binary_counts[e.cls], e.owner, 1)
            return
        self.class_totals[e.cls] += e.total
        for aid, n in e.counter.items():
            self._bump(self.class_author[e.cls], aid, n)
            self._bump(self.overall, aid, n)
            if e.multi:
                self._bump(self.multi_lines, aid, n)
        if len(e.counter) == 1 and e.total > 0:
            self.sole_lines[e.cls] += e.total
            self.sole_files[e.cls] += 1

    def on_commit(self, index: int, commit: Commit, touched: list,
                  state: CustodyState) -> None:
        ov = self.overlay
        for path in touched:
            if ov and path == ov.tarball_only_path:
                self.tarball_only_seen = True
            old = self.cache.pop(path, None)
            if old is not None:
                self._remove(old)
            entry: Optional[_FileEntry] = None
            if path in state.text:
                lines = state.text[path]
                entry = _FileEntry(cls=self.classify(path))
                entry.counter = dict(Counter(lines))
                entry.total = len(lines)
                entry.multi = len(state.ever_authors.get(path, ())) > 1
            elif path in state.binary:
                entry = _FileEntry(cls=self.classify(path), is_binary=True)
                entry.owner = state.binary[path]
            if entry is not None:
                self.cache[path] = entry
                self._add(entry)

        if ov:
            date_day = commit.date[:10]
            if any(p in touched for p in ov.paths) and (
                    ov.window[0] <= date_day < ov.window[1]):
                for p in ov.paths:
                    if p in touched:
                        e = self.cache.get(p)
                        self.overlay_events.append({
                            "path": p, "sha": commit.sha,
                            "author": commit.author, "date": commit.date,
                            "class": self.classify(p),
                            "binary": bool(e and e.is_binary),
                            "sole_custody": bool(e and not e.is_binary
                                                 and len(e.counter) == 1),
                            "second_author_contact": bool(e and e.multi),
                            "present_after": e is not None,
                        })

        self.snapshots.append(Snapshot(
            sha=commit.sha, date=commit.date, author=commit.author,
            class_totals=dict(self.class_totals),
            class_author={c: dict(d) for c, d in self.class_author.items()},
            overall=dict(self.overall),
            sole_lines=dict(self.sole_lines),
            sole_files=dict(self.sole_files),
            multi_lines=dict(self.multi_lines),
            binary_counts={c: dict(d) for c, d in self.binary_counts.items()},
        ))


def _grand_total(s: Snapshot) -> int:
    return sum(s.class_totals.values())


def principals_and_inversion(snaps: List[Snapshot], authors: List[str],
                             classes: tuple) -> dict:
    peak: dict = {}
    first_seen: dict = {}
    for i, s in enumerate(snaps):
        total = _grand_total(s) or 1
        for aid, n in s.overall.items():
            share = n / total
            if share > peak.get(aid, 0.0):
                peak[aid] = share
            if aid not in first_seen and n > 0:
                first_seen[aid] = i
    ranked = sorted(peak, key=lambda a: (-peak[a], authors[a]))
    if len(ranked) < 2:
        return {"principals": None, "note": "fewer than two authors with custody"}
    a, b = ranked[0], ranked[1]
    incumbent, challenger = (a, b) if first_seen[a] <= first_seen[b] else (b, a)

    def first_exceeds(get_inc, get_ch):
        for i, s in enumerate(snaps):
            if get_ch(s) > get_inc(s):
                return i
        return None

    inv_overall = first_exceeds(
        lambda s: s.overall.get(incumbent, 0),
        lambda s: s.overall.get(challenger, 0))
    inv_class = {
        c: first_exceeds(
            lambda s, c=c: s.class_author[c].get(incumbent, 0),
            lambda s, c=c: s.class_author[c].get(challenger, 0))
        for c in classes}
    return {
        "principals": {
            "incumbent": authors[incumbent],
            "challenger": authors[challenger],
            # integer-scaled, the payload float law (Campanile WS1, 2026-08-23):
            # the v0 float `peak_share` violated chain_receipt_core.canonical's
            # refusal and shipped 108 float paths into the sealed 2026Q3 bank —
            # recorded as a dated amendment on the Q3 prereg, never an edit.
            # Internal ranking arithmetic above stays float; only the EMITTED
            # payload is integer.
            "peak_share_e6": {authors[a]: int(round(peak[a] * 1_000_000)),
                              authors[b]: int(round(peak[b] * 1_000_000))},
        },
        "inversion_overall": inv_overall,
        "inversion_by_class": inv_class,
    }


def disclosure_index(snaps: List[Snapshot], disclosure_date: str) -> int:
    target = _date.fromisoformat(disclosure_date)
    best, best_key = 0, None
    for i, s in enumerate(snaps):
        dd = abs((_date.fromisoformat(s.date[:10]) - target).days)
        if best_key is None or dd < best_key:
            best, best_key = i, dd
    return best


def run_custody(repo: str, pin: str, classes: tuple,
                classify_fn: Callable[[str], str],
                overlay: Optional[OverlaySpec] = None,
                disclosure_date: Optional[str] = None) -> dict:
    """One repo -> measures. Refuses on pin mismatch (the census law)."""
    import subprocess
    from campanile.replay import GIT_PINS
    head = subprocess.run(["git", *GIT_PINS, "-C", repo, "rev-parse", pin],
                          check=True, capture_output=True).stdout.decode().strip()
    if head != pin:
        raise SystemExit(f"pin mismatch: {pin} resolves to {head}")
    mb = GenericMeasureBuilder(classes, classify_fn, overlay)
    final_state = replay(repo, pin, mb.on_commit)
    m3 = principals_and_inversion(mb.snapshots, final_state.authors, classes)
    out = {
        "pin": pin,
        "n_commits": len(mb.snapshots),
        "authors_n": len(final_state.authors),
        "m3": m3,
    }
    if disclosure_date:
        out["disclosure_chain_index"] = disclosure_index(mb.snapshots,
                                                         disclosure_date)
    out["_snapshots"] = mb.snapshots          # stripped before any artifact
    out["_authors"] = final_state.authors
    return out


__all__ = ["OverlaySpec", "GenericMeasureBuilder", "principals_and_inversion",
           "disclosure_index", "run_custody", "AUTHOR_FILTER_PEAK_SHARE"]
