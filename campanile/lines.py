"""lines — every sentence campanile prints or publishes lives here.

One module owns the words (so a wording decision is a one-line change and a
drift is an import error, not a shipped disagreement). Constants are
exact-render: the CLI and the README emit them verbatim, conformance tests
byte-compare them, and the fence scan (fence.py) runs over everything this
module renders. Incident references are structural and CVE-numbered.
"""
from __future__ import annotations

TOOL = "campanile"

WHAT = ("campanile replays a repository's git history and reports its "
        "line-custody structure — which author strings held which file "
        "classes, and when that structure shifted.")

METHOD_LINE = ("Only diff STRUCTURE is read: hunk arithmetic, paths, author "
               "strings. Content lines are consumed by count and never "
               "inspected — custody is pure arithmetic over the recorded "
               "diffs.")

OFFLINE_LINE = ("Verification is offline. The shipped xz fixture replays "
                "3,054 commits with no network, no clone, and no model.")

XZ_FINDING = ("In the xz repository (CVE-2024-3094), custody of the tests "
              "file class inverted at first-parent chain index 1746 — "
              "2023-03-13 — while overall custody never inverted. The "
              "payload that later shipped was carried in that same file "
              "class. This tool dates the structural shift; it makes no "
              "claim about intent, identity, or wrongdoing.")

FLEET_NEGATIVE = ("Calibration (2026Q3, the first 55-repo fleet): "
                  "class-level custody inversions are ordinary (46 of 55 "
                  "repos have them). Any class inverting while overall "
                  "custody never does: 2 of 55. The tests class "
                  "specifically — the xz signature — 0 of 55. The wider "
                  "fleet below measures the same signature at production "
                  "scale; a rate always travels with its denominator and "
                  "its epoch.")

REPLAY_GREEN = "replay: GREEN — the recorded structure reproduces the finding"
REPLAY_RED = "replay: RED — the result does not match the shipped expectation"
CLONE_MATCH = "from-clone: GREEN — a live clone at the pin tells the identical story"
CLONE_MISMATCH = "from-clone: RED — the live clone diverged from the fixture"
FIXTURE_OK = "fixture: pins hold (gzip and structural stream shas match the manifest)"
FIXTURE_BAD = "fixture: REFUSING — bytes do not match the shipped manifest"
VERIFY_RECEIPT_NOTE = ("what this proved: the receipt's signature and verdict "
                       "recompute over its recorded contents — binding, not "
                       "authorship")
VERIFY_VECTOR_GREEN = ("vector: GREEN — schema, fence fields, and the "
                       "integer-payload law all hold")
SCAN_FOOTER = ("author strings are repo-recorded personas; an inversion is a "
               "structural measurement, never an accusation")
NEEDS_VERIFY_EXTRA = ("this command needs the verify extra: "
                      "pip install 'campanile[verify]'")


def render_replay_report(fixture: dict, expected: dict, ok: bool,
                         clone_ok=None, personas: bool = False) -> str:
    m3 = fixture["m3"]
    inv = m3["inversion_by_class"]
    ps = m3["principals"]["peak_share_e6"]
    inc = m3["principals"]["incumbent"]
    ch = m3["principals"]["challenger"]
    if personas:
        share_line = ("  peak custody share (e6): "
                      + " · ".join(f"{k}={v}" for k, v in sorted(ps.items())))
    else:
        share_line = ("  peak custody share (e6): "
                      f"descending={ps[inc]} · ascending={ps[ch]}"
                      "  (author strings print with --personas)")
    lines = [
        f"{TOOL} replay xz — {fixture['n_commits']} commits at "
        f"{fixture['pin'][:12]}",
        METHOD_LINE,
        "",
        f"  tests-class inversion:  chain index {inv['tests']}  (2023-03-13)",
        f"  overall inversion:      {m3['inversion_overall']}",
        f"  disclosure chain index: {fixture['disclosure_chain_index']}",
        share_line,
        "",
        XZ_FINDING,
        "",
        REPLAY_GREEN if ok else REPLAY_RED,
    ]
    if clone_ok is not None:
        lines.append(CLONE_MATCH if clone_ok else CLONE_MISMATCH)
    return "\n".join(lines) + "\n"


PERSONAS_WITHHELD = ("principal author strings withheld from the printed "
                     "report — the JSON vector carries them beside the "
                     "in-schema fence fields; --personas prints them")
INVERSION_TAG = "structural measurement"


def render_scan_report(vec: dict, personas: bool = False) -> str:
    """Roles by default; persona strings only on request. The fence governs
    juxtaposition, not just vocabulary: a printed name beside an inversion
    line quotes as an accusation no matter how careful each word is, so the
    printed report speaks in roles and the JSON vector — where the fence
    fields travel with every event — carries the recorded personas."""
    lines = [
        f"{TOOL} scan — {vec['repo']} at {vec['pin'][:12]}: "
        f"{vec['n_commits']} commits, {vec['n_authors']} author strings",
    ]
    p = vec.get("principals")
    if not p:
        lines.append("  fewer than two author strings with custody — "
                     "no principals, no inversions to report")
    else:
        if personas:
            lines.append(f"  descending author: {p['incumbent']}")
            lines.append(f"  ascending author:  {p['challenger']}")
        else:
            lines.append(f"  ({PERSONAS_WITHHELD})")
        if vec["inversions"]:
            for e in vec["inversions"]:
                lines.append(f"  inversion [{e['class']}]: chain index "
                             f"{e['chain_index']} ({e['date'][:10]}) — "
                             f"{INVERSION_TAG}")
        else:
            lines.append(f"  checked {len(vec['classes'])} file classes — "
                         "no custody inversions")
        lines.append(f"  overall inversion: {vec['inversion_overall']}")
    lines.append(f"  ({SCAN_FOOTER})")
    return "\n".join(lines) + "\n"


AGENT_FOOTER = ("identity strings only, never content; a share is a reading "
                "of the record, not an identity claim")


def _pct(num, den):
    return f"{num * 100 / den:.2f}%" if den else "—"


def render_agent_report(agent: dict) -> str:
    """Agent-held custody: how many surviving lines are held by author
    identities that present as AI coding agents (generative) or as
    non-generative automation (mechanical). Shares only — no names."""
    lines = ["", "  agent-held custody at HEAD — identities PRESENTING AS "
                 "agents or automation, a reading of author strings:"]
    o = agent["overall"]
    if not o["gen"] and not o["mech"]:
        lines.append("    none — no agent or bot identity holds any "
                     "surviving line")
    else:
        lines.append(f"    overall: generative {_pct(o['gen'], o['total'])}"
                     f" · automation {_pct(o['mech'], o['total'])}"
                     f"  ({o['total']} lines)")
        for cname, d in sorted(agent["per_class"].items()):
            if d["gen"] or d["mech"]:
                lines.append(
                    f"    {cname}: generative {_pct(d['gen'], d['total'])}"
                    f" · automation {_pct(d['mech'], d['total'])}")
    lines.append(f"  ({AGENT_FOOTER})")
    return "\n".join(lines) + "\n"


BASE_RATES_WIDE = (
    "Measured on the sealed 406-repo top-PyPI fleet (2026Q4-wide), "
    "predictions staked before cloning. Three predicates, three separate "
    "questions. The bare xz shape in ANY file class — one class changes "
    "hands while the project overall never does: 64 of 406 healthy "
    "repositories. The same any-class shape with a 150-day "
    "recent-arrival condition on the ascending author: 36 of 406. The "
    "tests-class signature — the class that carried the xz payload, with "
    "no recent-arrival condition: 17 of 406, about 1 in 24. The earlier "
    "55-repo calibration above measured this same tests-class signature "
    "at 0 of 55: a small fleet's zero and a wide fleet's 1-in-24 are the "
    "same physics at different denominators, and both publish. At these "
    "rates the pattern alone accuses the innocent; that is the "
    "measurement, and it is why a match is a question, never a finding.")

FAQ_HAND_LINE = (
    "A campanile match is a structural measurement with a published base "
    "rate, never evidence of wrongdoing. The same shape appears in "
    "healthy, famous projects at the rates above; the usual cause is "
    "ordinary succession — someone takes over the tests while the founder "
    "keeps the whole. Reports speak in roles, and this project never "
    "publishes a named per-repository result — aggregates and sealed "
    "receipts only; whether a repository tells its own custody story is "
    "its maintainer's choice. If this section was linked at you, the number being "
    "cited asks a question about succession; it does not answer one "
    "about intent.")

AGENT_READOUT_README = (
    "Every scan ends with the agent-held custody readout: the share of "
    "surviving lines held by identities presenting as AI coding agents "
    "versus non-generative automation — shares only, no names. "
    "Classification reads the record; it never makes an identity claim, "
    "and a person named Claude or Devin never classifies as software.")


ENVELOPE_LINE = (
    "Predictions for the next quarterly sweep over the same fleet are "
    "already sealed: claims sha256 "
    "851d268b69b9e89ecaa1ebdd2c4d88e2720328e9469044db4a4e320d013c5fee, "
    "RFC 3161-witnessed 2026-08-24, unsealed October 2026. Whatever "
    "unseals either matches this hash or it does not; nobody — this "
    "project included — can edit it.")


def render_readme() -> str:
    from campanile.vector import WHAT_THIS_IS, WHAT_THIS_IS_NOT
    return f"""# {TOOL}

{WHAT}

{METHOD_LINE}

## The calibration case

```bash
uvx campanile replay xz
```

{XZ_FINDING}

{FLEET_NEGATIVE}

## Base rates

{BASE_RATES_WIDE}

## The sealed October envelope

{ENVELOPE_LINE}

{OFFLINE_LINE} `--from-clone PATH` recomputes the same result from a live
git clone at the pinned commit and refuses any other commit — proving the
fixture against the upstream history itself.

## Your own repository

```bash
uvx campanile scan .
```

Reports the repository's custody vector: per-class custody shares
(integer-scaled), principal roles (the recorded author strings live in the
JSON vector and print only with `--personas`), and any inversion events.
Every inversion event carries its meaning in-schema:

- what this is: {WHAT_THIS_IS}
- what this is not: {WHAT_THIS_IS_NOT}

{AGENT_READOUT_README}

## If someone files campanile output against your project

{FAQ_HAND_LINE}

## Verify

```bash
uvx campanile verify PATH
```

Dispatches on the file: a signed receipt (needs
`pip install 'campanile[verify]'`), a custody vector, or the fixture
manifest. All verification is offline.

## What ships in the sdist

The full test suite and the structural fixture — `pip download campanile
--no-binary :all:` gives a stranger everything needed to reproduce every
xz calibration number in this README, offline. The fleet numbers are
receipt-bound, not recomputable: the fleet bank is private under the
consent law, and the sealed receipt published beside the aggregate is what
a stranger verifies. The fixture contains git STRUCTURE only (shas, author
strings, paths, hunk arithmetic): no source code of the scanned repository
is redistributed.

Licensed Apache-2.0.
"""


# ===================================================================== v2 ==
# The disclosure decision table (one constant set -> DISCLOSURE.md and the
# page section render from THESE rows; a wording change is one edit here).
# Structural vocabulary throughout; the fence scan runs over every rendering.

SIGNATURE_CLASSES_V0 = ("tests",)

DISCLOSURE_TITLE = "disclosure protocol"
DISCLOSURE_PREAMBLE = (
    "The instrument measures structure, and the bare signature shape is a "
    "BASE-RATE EVENT — it appears in 17 of 406 healthy top-PyPI "
    "repositories (see README) and is never, by itself, escalated to "
    "anyone. This table governs only the FULL CONJUNCTION: the "
    "class-level signature (a class in SIGNATURE_CLASSES_V0 inverting "
    "while overall custody never does) TOGETHER WITH incumbent dormancy "
    "and contact with binary or opaque artifacts — published in advance "
    "so the procedure is a commitment rather than a reaction. "
    "Coordinator-first: an established coordinating body receives such an "
    "observation before anyone else, because a structural measurement "
    "about a living project deserves review by people equipped to weigh "
    "it. The consent law, in one sentence: this project never publishes "
    "a named per-repository result — aggregates and sealed receipts "
    "publish; names do not; the only path to an exception runs through "
    "this table.")

DISCLOSURE_ROW_ZERO = (
    "Row zero, absolute, and scoped to this project: any conjunction "
    "observation made by THIS PROJECT'S OWN fleet scans goes to project "
    "review first — no external contact of any kind precedes that "
    "review. Third-party users of the instrument are outside this "
    "table: what you observe in a repository you scan is yours to "
    "weigh, and the README's maintainer section is the suggested first "
    "read before contacting anyone.")

CERT_VINCE_URL = "https://www.kb.cert.org/vince/"
CERT_CVD_GUIDE_URL = "https://certcc.github.io/CERT-Guide-to-CVD/"
GH_ADVISORY_URL = ("https://docs.github.com/en/code-security/"
                   "security-advisories")

# (observed, evidence package, default route, clock)
DISCLOSURE_ROWS = (
    ("The bare signature shape, without the full conjunction, at any "
     "repository",
     "recorded internally only",
     "none — a base-rate event (17 of 406 healthy repositories); "
     "escalating it anywhere would accuse the innocent at 1 in 24",
     "re-measured at the next epoch"),
    ("The FULL CONJUNCTION at a living repository's current HEAD, "
     "reproducible at the pin",
     "a REDACTED custody vector — role labels in place of author strings, "
     "fence fields intact — plus method shas, the sealed preregistration "
     "reference, and a signed receipt; the unredacted vector stays sealed "
     "unless the coordinator requests it under their process",
     f"CERT/CC VINCE ({CERT_VINCE_URL})",
     f"the coordinator's own published process ({CERT_CVD_GUIDE_URL}) — "
     "cited, never invented; the repository's maintainers are notified "
     "promptly after coordinator acknowledgement, never surprised by "
     "publication"),
    ("The FULL CONJUNCTION in an archived or unmaintained repository",
     "the same redacted package",
     f"CERT/CC VINCE ({CERT_VINCE_URL}) — archived repositories cannot "
     f"receive repository-level advisories ({GH_ADVISORY_URL}), so the "
     "coordinator route holds",
     "no active-maintainer clock exists; publication only after "
     "coordinator acknowledgement and founder decision"),
    ("A conjunction observation that does not reproduce at the current "
     "pin",
     "recorded internally; no external contact",
     "none — re-measured at the next epoch",
     "none"),
)

DISCLOSURE_CONTACT = ("Questions about an observation, or a report "
                      "about this instrument's own output: "
                      "mars@cruxia.ai.")

DISCLOSURE_FOOTER = (
    "Every row reports a MEASUREMENT. What an inversion is and is not "
    "travels in-schema with every event object; the vocabulary above is "
    "structural by construction and checked by the fence scan.")


def render_disclosure_md() -> str:
    rows = "\n".join(
        f"| {o} | {e} | {r} | {c} |" for o, e, r, c in DISCLOSURE_ROWS)
    return f"""# {DISCLOSURE_TITLE}

{DISCLOSURE_PREAMBLE}

**{DISCLOSURE_ROW_ZERO}**

| observed | evidence package | default route | clock |
|---|---|---|---|
{rows}

{DISCLOSURE_FOOTER}

{DISCLOSURE_CONTACT}
"""
