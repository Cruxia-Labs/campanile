"""keys — the per-install signing key (ephemeral tier; never an org key).

Minted on first use into the user's state dir, chmod 0600, never printed.
What the key claims, stated plainly: CONTINUITY — the same key signing scan
after scan lets a verifier check one installation produced them. It claims
no identity, and the receipts' integrity claim is recomputation with the
key ignored entirely. Losing it is survivable: a fresh key mints and
continuity restarts; history still recomputes.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _state_dir() -> Path:
    root = os.environ.get("XDG_STATE_HOME")
    base = Path(root) if root else Path.home() / ".local" / "state"
    return base / "campanile"


def signing_key() -> Ed25519PrivateKey:
    """Load-or-mint the per-install key. 0600; never printed; never org."""
    d = _state_dir()
    d.mkdir(parents=True, exist_ok=True)
    seed_path = d / "signing_seed.b64"
    if seed_path.is_file():
        seed = base64.b64decode(seed_path.read_text(encoding="ascii").strip())
        return Ed25519PrivateKey.from_private_bytes(seed)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    fd = os.open(seed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(seed).decode("ascii") + "\n")
    return key


def key_fingerprint(key: Ed25519PrivateKey) -> str:
    """sha256 of the raw PUBLIC bytes, first 16 hex — safe to log."""
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(pub).hexdigest()[:16]


__all__ = ["signing_key", "key_fingerprint"]
