"""receipts — mint-local, verify-anywhere (the `verify` extra).

`receipt.py` mints signed action receipts (Ed25519 over RFC 8785 canonical
bytes, `canonical.py` — which REFUSES floats, the reason every campanile
payload is integer-scaled). `keys.py` holds a per-install signing key. The
key claims CONTINUITY of one installation's scans, never identity — the
integrity claim is recomputation, with the key ignored entirely. Verifying
anyone's receipt needs only `er1_verify.py`, one file, offline.
"""
