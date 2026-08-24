"""vector — the per-repo custody vector, fence-schema enforced.

One repo's replay folds down to one vector: final-state custody shares per
class (integer-scaled _e6 — the payload float law), a downsampled series, and
the INVERSION EVENTS. The fence is SCHEMA, not prose: every inversion object
carries the literal fields below, `require_fence` refuses any object without
the exact bytes, and fence.py bans accusation vocabulary from every artifact.

Author strings are repo-recorded personas, reported verbatim and deliberately
unmerged across repos — no identity resolution exists anywhere in this tool.
"""
from __future__ import annotations

from typing import List

WHAT_THIS_IS = ("the date one author string's line custody in one file class "
                "first exceeded another's")
WHAT_THIS_IS_NOT = ("not an accusation, not a compromise indicator, not an "
                    "identity claim; author strings are repo-recorded personas")
FENCE_FIELDS = {"finding_kind": "custody_inversion",
                "signal_class": "STRUCTURAL",
                "what_this_is": WHAT_THIS_IS,
                "what_this_is_not": WHAT_THIS_IS_NOT}


def require_fence(event: dict) -> None:
    """Refuse any inversion object without the exact fence bytes."""
    for k, v in FENCE_FIELDS.items():
        if event.get(k) != v:
            raise ValueError(
                f"REFUSING: inversion event lacks the exact fence field {k!r} "
                "— the fence is schema, not prose")


def _share_e6(d: dict, aid: int, total: int) -> int:
    return (1_000_000 * d.get(aid, 0)) // max(total, 1)


def build_vector(repo_name: str, result: dict, classes: tuple,
                 downsample_to: int = 100) -> dict:
    """Fold a run_custody() result into the sealed vector shape."""
    snaps = result["_snapshots"]
    authors = result["_authors"]
    m3 = result["m3"]
    events: List[dict] = []
    principals = m3.get("principals")
    if principals:
        name_to_id = {n: i for i, n in enumerate(authors)}
        inc = name_to_id[principals["incumbent"]]
        ch = name_to_id[principals["challenger"]]
        for c, idx in (m3.get("inversion_by_class") or {}).items():
            if idx is not None:
                events.append({**FENCE_FIELDS, "class": c, "chain_index": idx,
                               "date": snaps[idx].date, "sha": snaps[idx].sha})
        if m3.get("inversion_overall") is not None:
            idx = m3["inversion_overall"]
            events.append({**FENCE_FIELDS, "class": "overall",
                           "chain_index": idx, "date": snaps[idx].date,
                           "sha": snaps[idx].sha})
    for e in events:
        require_fence(e)

    final = snaps[-1] if snaps else None
    custody = {}
    if final is not None and principals:
        for c in classes:
            total = final.class_totals.get(c, 0)
            custody[c] = {
                "total_lines": total,
                "incumbent_share_e6": _share_e6(final.class_author[c], inc, total),
                "challenger_share_e6": _share_e6(final.class_author[c], ch, total),
                "sole_lines": final.sole_lines.get(c, 0),
            }
    n = len(snaps)
    step = max(1, n // downsample_to)
    series = []
    if principals:
        for i in range(0, n, step):
            s = snaps[i]
            tot = sum(s.class_totals.values()) or 1
            series.append({"i": i, "date": s.date[:10],
                           "incumbent_share_e6": _share_e6(s.overall, inc, tot),
                           "challenger_share_e6": _share_e6(s.overall, ch, tot)})
    return {
        "schema": "campanile-vector/v1",
        "repo": repo_name,
        "pin": result["pin"],
        "n_commits": result["n_commits"],
        "n_authors": result["authors_n"],
        "classes": list(classes),
        "principals": principals,
        "custody_final": custody,
        "series_downsampled": series,
        "inversions": events,
        "inversion_overall": m3.get("inversion_overall"),
    }


__all__ = ["FENCE_FIELDS", "WHAT_THIS_IS", "WHAT_THIS_IS_NOT",
           "require_fence", "build_vector"]
