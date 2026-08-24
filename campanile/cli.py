"""cli — replay · scan · verify.

Core commands are pure stdlib + the git binary. Receipt verification and
minting live behind the `verify` extra (`cryptography`); everything else
refuses nothing and phones nothing.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from campanile import lines as L

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture_lines(gz_path: Path):
    with gzip.open(gz_path, "rb") as fh:
        yield from fh


def _check_fixture(fx: Path) -> dict:
    man = json.loads((fx / "FIXTURE_MANIFEST.json").read_text(encoding="utf-8"))
    gz = fx / "structural.log.gz"
    if hashlib.sha256(gz.read_bytes()).hexdigest() != man["gz_sha256"]:
        raise SystemExit(L.FIXTURE_BAD)
    return man


def _xz_measure(replay_call) -> dict:
    from campanile.classify_xz import CLASSES, classify
    from campanile.custody import (GenericMeasureBuilder, OverlaySpec,
                                   disclosure_index, principals_and_inversion)
    from campanile.xz_constants import (DISCLOSURE_DATE, OVERLAY_PATHS,
                                        OVERLAY_WINDOW, TARBALL_ONLY_PATH,
                                        XZ_PIN)
    spec = OverlaySpec(paths=OVERLAY_PATHS, window=OVERLAY_WINDOW,
                       tarball_only_path=TARBALL_ONLY_PATH)
    mb = GenericMeasureBuilder(CLASSES, classify, spec)
    final = replay_call(mb.on_commit)
    m3 = principals_and_inversion(mb.snapshots, final.authors, CLASSES)
    return {"m3": m3,
            "disclosure_chain_index": disclosure_index(mb.snapshots,
                                                       DISCLOSURE_DATE),
            "n_commits": len(mb.snapshots), "pin": XZ_PIN}


def cmd_replay(args) -> int:
    if args.case != "xz":
        print(f"unknown case {args.case!r} — shipped cases: xz",
              file=sys.stderr)
        return 2
    from campanile.replay import replay_from_lines
    fx = FIXTURES / "xz"
    _check_fixture(fx)
    expected = json.loads((fx / "expected.json").read_text(encoding="utf-8"))
    got = _xz_measure(lambda cb: replay_from_lines(
        _fixture_lines(fx / "structural.log.gz"), cb, structural_only=True))
    ok = got == expected
    clone_ok = None
    if args.from_clone:
        from campanile.replay import replay
        from campanile.xz_constants import XZ_PIN
        live = _xz_measure(lambda cb: replay(args.from_clone, XZ_PIN, cb))
        clone_ok = live == got
    print(L.render_replay_report(got, expected, ok, clone_ok,
                                 personas=args.personas), end="")
    return 0 if ok and clone_ok is not False else 1


def cmd_scan(args) -> int:
    from campanile.classify_generic import GENERIC_CLASSES, classify_generic
    from campanile.custody import run_custody
    from campanile.fence import scan_bytes
    from campanile.replay import GIT_PINS
    from campanile.vector import build_vector
    repo = Path(args.path).resolve()
    pin = subprocess.run(["git", *GIT_PINS, "-C", str(repo), "rev-parse",
                          "HEAD"], check=True, capture_output=True
                         ).stdout.decode().strip()
    result = run_custody(str(repo), pin, GENERIC_CLASSES, classify_generic)
    vec = build_vector(repo.name, result, GENERIC_CLASSES)
    hits = scan_bytes(json.dumps(_fence_view(vec)).encode())
    if hits:
        print(f"FENCE RED: output contains {hits} — refusing to emit",
              file=sys.stderr)
        return 2
    if args.json:
        Path(args.json).write_text(
            json.dumps(vec, indent=1, sort_keys=True) + "\n",
            encoding="utf-8")
    print(L.render_scan_report(vec, personas=args.personas), end="")
    print(L.render_agent_report(_agent_shares(repo, result)), end="")
    return 0


def _fence_view(vec: dict) -> dict:
    """The fence polices THIS TOOL'S vocabulary, not the scanned
    repository's. Repo-supplied strings (repo name, recorded author
    strings) are data, not our speech — an innocent repository named
    for the very thing it defends against must not brick its own
    report — so they are replaced with role placeholders before the
    scan; everything the tool itself says is scanned verbatim."""
    view = json.loads(json.dumps(vec))
    view["repo"] = "(repo)"
    p = view.get("principals")
    if p:
        shares = p.get("peak_share_e6", {})
        p["peak_share_e6"] = {
            "(descending)": shares.get(p.get("incumbent")),
            "(ascending)": shares.get(p.get("challenger")),
        }
        p["incumbent"] = "(descending)"
        p["challenger"] = "(ascending)"
    return view


def _agent_shares(repo: Path, result: dict) -> dict:
    """Agent-held custody at HEAD from the final snapshot. Integer line
    counts only; classification per campanile.agent_identity."""
    from campanile.agent_identity import classify_identity
    from campanile.replay import GIT_PINS
    final = result["_snapshots"][-1]
    authors = result["_authors"]  # list; index IS the author id
    raw = subprocess.run(["git", *GIT_PINS, "-C", str(repo), "log",
                          "--format=%an\t%ae"], check=True,
                         capture_output=True).stdout.decode("utf-8",
                                                            "replace")
    emails: dict = {}
    for line in raw.splitlines():
        if "\t" in line:
            n, e = line.split("\t", 1)
            emails.setdefault(n, set()).add(e)
    cls = {aid: classify_identity(name, emails.get(name, ()))
           for aid, name in enumerate(authors)}

    def fold(d):
        return {"total": sum(d.values()),
                "gen": sum(n for a, n in d.items()
                           if cls.get(a) == "generative"),
                "mech": sum(n for a, n in d.items()
                            if cls.get(a) == "mechanical")}

    return {"overall": fold(final.overall),
            "per_class": {c: fold(d)
                          for c, d in final.class_author.items()}}


def cmd_verify(args) -> int:
    p = Path(args.path)
    doc = json.loads(p.read_text(encoding="utf-8"))
    if "schema_version" in doc:  # a signed er1 receipt
        try:
            import cryptography  # noqa: F401
        except ImportError:
            print(L.NEEDS_VERIFY_EXTRA, file=sys.stderr)
            return 2
        rc = subprocess.run([sys.executable, "-m", "campanile.er1_verify",
                             str(p)]).returncode
        if rc == 0:
            print(L.VERIFY_RECEIPT_NOTE)
        return rc
    schema = doc.get("schema", "")
    if schema == "campanile-vector/v1":
        from campanile.fence import scan_bytes
        from campanile.vector import require_fence
        for e in doc.get("inversions", []):
            require_fence(e)
        def _floats(o):
            if isinstance(o, float):
                return True
            if isinstance(o, dict):
                return any(_floats(v) for v in o.values())
            if isinstance(o, list):
                return any(_floats(v) for v in o)
            return False
        if _floats(doc):
            print("RED: vector carries float payloads", file=sys.stderr)
            return 1
        hits = scan_bytes(p.read_bytes())
        if hits:
            print(f"RED: fence lexicon {hits}", file=sys.stderr)
            return 1
        print(L.VERIFY_VECTOR_GREEN)
        return 0
    if schema == "campanile-fixture/v1":
        # the verification binds to the FILE THE USER PASSED (WS8 catch:
        # verifying only the shipped copy while ignoring PATH gave false
        # assurance about arbitrary manifests)
        fx = FIXTURES / "xz"
        shipped = (fx / "FIXTURE_MANIFEST.json").read_bytes()
        if p.read_bytes() != shipped:
            print("RED: this manifest does not match the shipped fixture "
                  "manifest byte-for-byte", file=sys.stderr)
            return 1
        _check_fixture(fx)
        print(L.FIXTURE_OK)
        return 0
    print(f"unrecognized document (schema={schema!r})", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog=L.TOOL, description=L.WHAT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("replay", help="replay a shipped calibration case")
    p.add_argument("case")
    p.add_argument("--from-clone", metavar="PATH",
                   help="also recompute from a live git clone at the pin")
    p.add_argument("--personas", action="store_true",
                   help="print recorded author strings instead of roles")
    p.set_defaults(fn=cmd_replay)
    p = sub.add_parser("scan", help="custody vector of a local repository")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--json", metavar="FILE", help="also write the vector JSON")
    p.add_argument("--personas", action="store_true",
                   help="print recorded author strings instead of roles")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("verify", help="verify a receipt, vector, or manifest")
    p.add_argument("path")
    p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("prereg",
                       help="seal/verify/amend a preregistered study")
    p.add_argument("rest", nargs=argparse.REMAINDER)
    p.set_defaults(fn=lambda a: __import__(
        "campanile.prereg", fromlist=["main"]).main(a.rest))
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
