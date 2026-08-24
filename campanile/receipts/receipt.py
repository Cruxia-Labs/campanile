"""The Action Receipt — signed, chained, offline-verifiable record of a preflight decision.

Reuses the proven primitives from `chain_receipt_core`:
  - `canonical_json` (RFC 8785 canonical serialization — sorted keys, compact; NO Unicode
    normalization — NFC was dropped 2026-08-05, CANON_VERSION 2: strings sign as parsed),
  - SHA-256 over the canonical body with `signature := null`,
  - Ed25519 over the raw 32-byte digest (b64url-encoded keys/sigs).

The schema carries the irreversible monetization/standard seams the boards said are
now-or-never (the signature covers the schema, so they cannot be retrofitted): per-belief
`source_kind`, `action_binding`, the receipt `chain`, `belief_class`/`halt_eligible`,
`coverage`, key/verification tiers, and witness slots.

Determinism fence (#3): `receipt_id` and `created_at` are signed metadata but are NOT
part of the *verified claim* — the verifier re-runs the conflict predicate over the
recorded beliefs + action, not over the timestamp/uuid.
"""
from __future__ import annotations

import base64
import copy
import datetime as _dt
import hashlib
import uuid
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from campanile.receipts.canonical import canonical_json

SCHEMA_VERSION = "action-receipt/v0"
OPERATOR_VERSION = "campanile/0.1"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_decode_exact(s: str, *, length: int) -> bytes:
    """Decode CANONICAL unpadded base64url of an exact byte length, or raise ValueError.

    `_b64url_decode` accepts several spellings of the same bytes — padded, and the standard
    `+/` alphabet — so the signature TEXT of a receipt could be rewritten while verification
    still passed. That contradicts the guarantee this format is sold on ("flip a single byte
    and verification fails"): two byte-different receipt files verified identically, which
    defeats any equality or dedup check keyed on the receipt as a document.

    The fix is to require the one canonical spelling and re-encode to prove it: decode, then
    check the input is exactly what encoding those bytes produces. Nothing we mint is
    affected — the producer has always emitted unpadded urlsafe — so this rejects only
    receipts whose signature block was rewritten after signing."""
    if not isinstance(s, str):
        raise ValueError("expected a base64url string")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if len(raw) != length:
        raise ValueError(f"expected {length} bytes, got {len(raw)}")
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        raise ValueError("non-canonical base64url encoding")
    return raw


def _now_rfc3339() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def args_hash(tool: str, asserts: dict, resource: str) -> str:
    """Bind the receipt to the exact tool request (the `action_binding`)."""
    return sha256_hex(canonical_json({"tool": tool, "asserts": asserts, "resource": resource}))


def state_root(belief_records: list) -> str:
    """Content-addressed root over the ordered belief snapshot (the pre/post state root)."""
    return sha256_hex(canonical_json(belief_records))


def generate_keypair() -> tuple[Ed25519PrivateKey, str]:
    """Return (private_key, base64url raw public-key string)."""
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return sk, _b64url(pub)


def receipt_body_for_hash(receipt: dict) -> dict:
    """The receipt with `signature := None` — what gets canonicalized + hashed + signed.

    deepcopy, not dict(): a shallow copy shares the nested `decision`/`action`/`beliefs`
    dicts with the caller, so a later mutation of any of them would silently change the
    bytes this function is supposed to have frozen. The cost is negligible next to the
    hash, and a canonicalizer that can be retroactively altered is not one."""
    body = copy.deepcopy(receipt)
    body["signature"] = None
    return body


def receipt_hash(receipt: dict) -> str:
    return sha256_hex(canonical_json(receipt_body_for_hash(receipt)))


def receipt_digest(receipt: dict) -> bytes:
    return hashlib.sha256(canonical_json(receipt_body_for_hash(receipt))).digest()


def sign(receipt: dict, sk: Ed25519PrivateKey) -> dict:
    """Return a new receipt dict with the Ed25519 signature filled in."""
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    sig = sk.sign(receipt_digest(receipt))
    out = dict(receipt)
    out["signature"] = {
        "algorithm": "ed25519",
        "public_key": _b64url(pub),
        "signature": _b64url(sig),
    }
    return out


def verify_signature(receipt: dict) -> bool:
    """True iff the embedded Ed25519 signature verifies the canonical body (tamper-evident)."""
    sigblock = receipt.get("signature")
    if not sigblock or sigblock.get("algorithm") != "ed25519":
        return False
    try:
        # Ed25519: a public key is exactly 32 bytes and a signature exactly 64.
        pub = _b64url_decode_exact(sigblock["public_key"], length=32)
        sig = _b64url_decode_exact(sigblock["signature"], length=64)
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, receipt_digest(receipt))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def chain_root_from_seed(seed: bytes) -> str:
    return sha256_hex(seed)


def _coverage(unevaluated: Optional[list]) -> dict:
    """The receipt's coverage block.

    `unevaluated_constraints` is present ONLY when there is something to report. That is not
    tidiness — the golden vectors are a frozen, published conformance corpus that the live
    er1-verify 1.0.0 checks, and adding a key to every receipt changes every receipt hash and
    breaks them. A field that appears only when it carries information leaves untouched receipts
    byte-identical to the ones already published, so this stays an additive signal rather than a
    format change. test_regeneration_is_byte_identical is what caught the difference.
    """
    cov = {"certified_modules": ["typed-config"], "exclusions": ["nl_extraction"]}
    if unevaluated:
        cov["unevaluated_constraints"] = unevaluated
    return cov


def build_receipt(
    *,
    decision: dict,
    beliefs: list,                 # list of belief_to_record(...) dicts
    action: dict,                  # raw {tool, asserts, resource} — lets the verifier recompute
    pre_state_root: str,
    post_state_root: Optional[str],
    prev_receipt_hash: str,
    chain_root_hash: str,
    sequence_number: int,
    key_tier: str = "ephemeral",
    unevaluated: Optional[list] = None,
    verification_tier: str = "local",
    operator_version: str = OPERATOR_VERSION,
    receipt_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> dict:
    """Assemble an unsigned action receipt (call `sign()` next)."""
    tool = action.get("tool", "")
    asserts = action.get("asserts", {})
    resource = action.get("resource", "")
    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_id": receipt_id or str(uuid.uuid4()),
        "created_at": created_at or _now_rfc3339(),
        "chain": {
            "prev_receipt_hash": prev_receipt_hash,
            "chain_root_hash": chain_root_hash,
            "sequence_number": sequence_number,
        },
        "pre_state_root": pre_state_root,
        "post_state_root": post_state_root,
        "action": {"tool": tool, "asserts": asserts, "resource": resource},
        "action_binding": {
            "tool": tool,
            "args_hash": args_hash(tool, asserts, resource),
            "resource": resource,
        },
        "beliefs": beliefs,
        "decision": decision,
        "coverage": _coverage(unevaluated),
        "operator_version": operator_version,
        "key_tier": key_tier,
        "verification_tier": verification_tier,
        "witnesses": [],          # multi-signer slots (operator/org/witness) — empty for now
        "signature": None,
    }


__all__ = [
    "SCHEMA_VERSION", "OPERATOR_VERSION",
    "generate_keypair", "sign", "verify_signature",
    "receipt_hash", "receipt_digest", "args_hash", "sha256_hex",
    "chain_root_from_seed", "build_receipt",
]
