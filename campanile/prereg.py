"""prereg — commit now, open later, verify forever.

A study is a directory: CLAIMS.md (staked predictions INCLUDING the boring
outcome — a pre-committed null is what makes a null publishable), a sealed
target list (committed as a hash while the entries stay private), method file
pins, and an append-only receipt ledger. `verify` runs offline, forever —
including on studies sealed by OTHER implementations of this format
(prereg/v0): the commitment is RFC 8785 canonical bytes of the sorted
[{path, sha256}] entries, ancestor-relative, so no machine path ever enters
the commitment.

  campanile prereg seal STUDY --targets P [P ...] --method F [F ...]
  campanile prereg verify STUDY [--against-files BASE]
  campanile prereg amend STUDY --note TEXT

Sealing and amending mint receipts and need the `verify` extra; verifying a
study's structure (claims prefix, commitment) is pure stdlib, and its
receipts are checked when the extra is present — the output always states
what was and was not checked. External time witnesses stamped by other
tooling are reported as present-but-not-checked, never as verified.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

SCHEMA = "prereg/v0"
EXCLUDE_NAMES = {".git", "__pycache__", ".DS_Store"}


def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _expand(paths: list) -> list:
    files = []
    for raw in paths:
        p = Path(raw).resolve()
        if not p.exists():
            raise SystemExit(f"no such path: {raw}")
        if p.is_dir():
            files += [f for f in sorted(p.rglob("*"))
                      if f.is_file() and f.name not in EXCLUDE_NAMES
                      and f.suffix != ".pyc"
                      and not any(part in EXCLUDE_NAMES for part in f.parts)]
        else:
            files.append(p)
    if not files:
        raise SystemExit("nothing to seal")
    return files


def _entries(files: list) -> list:
    if len(files) == 1:
        base = files[0].parent
    else:
        groups = [list(f.parent.parts) for f in files]
        common = []
        for g in zip(*groups):
            if all(x == g[0] for x in g):
                common.append(g[0])
            else:
                break
        if not common:
            raise SystemExit("inputs share no common ancestor")
        base = Path(*common)
    out = [{"path": f.relative_to(base).as_posix(),
            "sha256": "sha256:" + _sha_file(f)} for f in files]
    out.sort(key=lambda e: e["path"])
    seen = set()
    for e in out:
        if e["path"] in seen:
            raise SystemExit(f"duplicate relative path: {e['path']}")
        seen.add(e["path"])
    return out


def commitment_hash(entries: list) -> str:
    from campanile.receipts.canonical import canonical_json
    body = [{"path": e["path"], "sha256": e["sha256"]} for e in entries]
    return "sha256:" + hashlib.sha256(canonical_json(body)).hexdigest()


def cmd_seal(study: Path, targets: list, methods: list) -> int:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import \
            Ed25519PrivateKey  # noqa: F401
    except ImportError:
        print("sealing mints a receipt — pip install 'campanile[verify]'",
              file=sys.stderr)
        return 2
    from campanile.receipts.receipt import (build_receipt, receipt_hash,
                                            sign, state_root,
                                            verify_signature)
    from campanile.receipts.keys import signing_key
    study.mkdir(parents=True, exist_ok=True)
    claims_p = study / "CLAIMS.md"
    if not claims_p.is_file():
        print(f"REFUSING: no CLAIMS.md in {study} — stake the predictions "
              "(including the boring outcome) before sealing anything",
              file=sys.stderr)
        return 2
    raw = claims_p.read_bytes()
    pin = {"schema": "campanile:claim-bundle/v1",
           "claims_sha256": hashlib.sha256(raw).hexdigest(),
           "frozen_length": len(raw),
           "frozen_prefix_sha256": hashlib.sha256(raw).hexdigest()}
    (study / "PIN.json").write_text(
        json.dumps(pin, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    entries = _entries(_expand(targets))
    commitment = commitment_hash(entries)
    (study / "targets.commitment.json").write_text(json.dumps(
        {"schema": "prereg-targets/v0", "commitment_hash": commitment,
         "n_entries": len(entries), "entries": entries},
        indent=1, sort_keys=True) + "\n", encoding="utf-8")

    import os
    # stored method paths are cwd-relative — no machine path enters the study
    method_pins = [{"path": os.path.relpath(m), "sha256": _sha_file(Path(m))}
                   for m in sorted(methods)]
    beliefs = ([{"belief_id": "prereg-claims", "belief_class": "CERTIFIED",
                 "entity": "doc:CLAIMS.md", "rule": "equals",
                 "value": f"sha256:{pin['claims_sha256']}",
                 "source_kind": "deterministic", "status": "active"},
                {"belief_id": "prereg-targets", "belief_class": "CERTIFIED",
                 "entity": "targets:commitment", "rule": "equals",
                 "value": commitment, "source_kind": "deterministic",
                 "status": "active"}]
               + [{"belief_id": f"prereg-method-{i}",
                   "belief_class": "CERTIFIED",
                   "entity": f"method:{Path(m['path']).name}",
                   "rule": "equals", "value": f"sha256:{m['sha256']}",
                   "source_kind": "deterministic", "status": "active"}
                  for i, m in enumerate(method_pins)])
    root = state_root(beliefs)
    GENESIS = "0" * 64
    rec = build_receipt(
        beliefs=beliefs,
        decision={"verdict": "ALLOW", "reason_code": "COHERENT",
                  "conflicting_belief_id": None, "entity": None,
                  "current": None, "proposed": None},
        action={"tool": "campanile.prereg.seal", "asserts": {},
                "resource": f"prereg:{study.name}"},
        pre_state_root=root, post_state_root=root,
        prev_receipt_hash=GENESIS, chain_root_hash=GENESIS,
        sequence_number=0, receipt_id=f"prereg-{study.name}",
    )
    rec = sign(rec, signing_key())
    assert verify_signature(rec)
    with open(study / "receipts.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    manifest = {"schema": SCHEMA, "study": study.name,
                "claims_sha256": pin["claims_sha256"],
                "frozen_length": pin["frozen_length"],
                "frozen_prefix_sha256": pin["frozen_prefix_sha256"],
                "targets_commitment": commitment,
                "n_targets": len(entries), "methods": method_pins,
                "receipt_hash": receipt_hash(rec), "amendments": []}
    (study / "PREREG.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n",
        encoding="utf-8")
    print(f"sealed: {study.name}  claims sha256:"
          f"{pin['claims_sha256'][:16]}…  targets {commitment[:23]}…")
    return 0


def cmd_verify(study: Path, against_files=None) -> int:
    ok = True
    man = json.loads((study / "PREREG.json").read_text(encoding="utf-8"))
    raw = (study / "CLAIMS.md").read_bytes()
    if hashlib.sha256(raw[:man["frozen_length"]]).hexdigest() != \
            man["frozen_prefix_sha256"]:
        print("RED: frozen claims prefix changed", file=sys.stderr)
        ok = False
    tc = json.loads((study / "targets.commitment.json"
                     ).read_text(encoding="utf-8"))
    if commitment_hash(tc["entries"]) != man["targets_commitment"] or \
            tc["commitment_hash"] != man["targets_commitment"]:
        print("RED: targets commitment does not recompute", file=sys.stderr)
        ok = False
    if against_files:
        base = Path(against_files)
        for e in tc["entries"]:
            p = base / e["path"]
            want = e["sha256"].split(":", 1)[-1]
            if not p.is_file() or _sha_file(p) != want:
                print(f"RED: revealed target differs: {e['path']}",
                      file=sys.stderr)
                ok = False
    try:
        import cryptography  # noqa: F401
        have_crypto = True
    except ImportError:
        have_crypto = False
    ledger = study / "receipts.jsonl"
    if have_crypto and ledger.is_file():
        from campanile import er1_verify as EV
        recs = [json.loads(l) for l in
                ledger.read_text(encoding="utf-8").splitlines()]
        for rec in recs:
            res = EV.verify(rec)
            if not res.get("ok"):
                print(f"RED: study receipt fails: {res}", file=sys.stderr)
                ok = False
        values = {b["value"] for rec in recs
                  for b in rec.get("beliefs", [])}
        for want in (f"sha256:{man['claims_sha256']}",
                     man["targets_commitment"]):
            if want not in values:
                print(f"RED: receipt beliefs do not bind {want[:30]}…",
                      file=sys.stderr)
                ok = False
        print(f"receipts: {len(recs)} checked")
    elif ledger.is_file():
        print("receipts: present, NOT checked (needs 'campanile[verify]')")
    if (study / "PREREG.witness.json").is_file():
        print("witnesses: present, NOT checked by this implementation")
    print("prereg verify:", "GREEN" if ok else "RED")
    return 0 if ok else 1


def cmd_amend(study: Path, note: str) -> int:
    with open(study / "CLAIMS.md", "a", encoding="utf-8") as f:
        f.write(f"\n---\nAMENDMENT: {note}\n")
    man_p = study / "PREREG.json"
    man = json.loads(man_p.read_text(encoding="utf-8"))
    man["amendments"].append({"note": note})
    man_p.write_text(json.dumps(man, indent=1, sort_keys=True) + "\n",
                     encoding="utf-8")
    print("amended (appended below the frozen prefix; the prefix never moves)")
    return 0


def main(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="campanile prereg")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("seal"); p.add_argument("study")
    p.add_argument("--targets", nargs="+", required=True)
    p.add_argument("--method", nargs="+", required=True)
    p = sub.add_parser("verify"); p.add_argument("study")
    p.add_argument("--against-files")
    p = sub.add_parser("amend"); p.add_argument("study")
    p.add_argument("--note", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "seal":
        return cmd_seal(Path(a.study), a.targets, a.method)
    if a.cmd == "verify":
        return cmd_verify(Path(a.study), a.against_files)
    return cmd_amend(Path(a.study), a.note)
