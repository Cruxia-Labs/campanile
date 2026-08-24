"""Mint locally, verify with the one-file verifier — the whole loop, offline.

Needs the `verify` extra; skipped cleanly without it. The key is per-install
and ephemeral-tier by construction: `build_receipt`'s default is never
overridden anywhere in this package, so an org-tier campanile receipt cannot
exist.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

from campanile.receipts.canonical import canonical_json  # noqa: E402
from campanile.receipts.receipt import (build_receipt, receipt_hash,  # noqa: E402
                                        sign, state_root, verify_signature)

GENESIS = "0" * 64


def _mint(tmp: Path) -> Path:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import \
        Ed25519PrivateKey
    beliefs = [{"belief_id": "scan", "belief_class": "CERTIFIED",
                "entity": "vector:sha256", "rule": "equals",
                "value": "sha256:" + "ab" * 32,
                "source_kind": "deterministic", "status": "active"}]
    root = state_root(beliefs)
    rec = build_receipt(
        beliefs=beliefs,
        decision={"verdict": "ALLOW", "reason_code": "COHERENT",
                  "conflicting_belief_id": None, "entity": None,
                  "current": None, "proposed": None},
        action={"tool": "campanile.scan", "asserts": {},
                "resource": "vector:test"},
        pre_state_root=root, post_state_root=root,
        prev_receipt_hash=GENESIS, chain_root_hash=GENESIS,
        sequence_number=0, receipt_id="campanile-test-receipt",
        created_at="1970-01-01T00:00:00Z",
    )
    rec = sign(rec, Ed25519PrivateKey.generate())
    assert verify_signature(rec)
    p = tmp / "scan.er1.json"
    p.write_text(json.dumps(rec, sort_keys=True, separators=(",", ":")),
                 encoding="utf-8")
    return p


def test_mint_then_one_file_verify():
    with tempfile.TemporaryDirectory() as td:
        p = _mint(Path(td))
        rc = subprocess.run([sys.executable, "-m", "campanile.er1_verify",
                             str(p)], capture_output=True)
        assert rc.returncode == 0, rc.stdout + rc.stderr


def test_ephemeral_tier_by_construction():
    with tempfile.TemporaryDirectory() as td:
        rec = json.loads(_mint(Path(td)).read_text(encoding="utf-8"))
        assert rec["key_tier"] == "ephemeral"


def test_canonical_refuses_floats():
    with pytest.raises(ValueError):
        canonical_json({"share": 0.5})
    assert canonical_json({"share_e6": 500000})


def test_golden_vectors_byte_pin():
    import hashlib
    p = Path(__file__).resolve().parent / "golden_vectors.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc, "golden vectors present and non-empty"
    # the byte pin — deep conformance lives in the verifier's home repo
    assert hashlib.sha256(p.read_bytes()).hexdigest() == \
        "c5945436c5ad2d1addb4976722b5b8ee9b7ad7536fac314c1dfb6a4f98c4e4d6"
