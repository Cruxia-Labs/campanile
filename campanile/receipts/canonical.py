"""Canonical JSON serializer (RFC 8785–compatible).

Rules (see SCHEMA.md §4):
  1. Object keys sorted by UTF-16 code-unit order (== lex order on
     ASCII subset; for non-ASCII keys we use the same code-unit sort
     as JavaScript's default Array.sort()).
  2. No whitespace.
  3. Strings are serialized AS PARSED — no normalization; non-ASCII
     escaped as \\uXXXX (lower hex). Surrogate pairs for codepoints
     > U+FFFF.
  4. Numbers: integers as-is; floats via shortest-roundtrip repr.
  5. null / true / false as bare literals.
  6. No trailing newline.

CORRECTION (2026-08-05): rule 3 previously NFC-normalized every string
before serialization. That diverged from the ER1 frozen canon ("no
normalization — strings are serialized as parsed", er1-spec
CONFORMANCE.md), and it was measured to matter: a signed preflight
receipt whose belief value was in NFD form (what macOS filesystems
produce) FAILED under the published er1-verify 1.0.0 — the producer
hashed and signed NFC bytes while emitting raw bytes. The ASCII-only
golden vectors could never catch it. NFC also binds the hash to the
running interpreter's Unicode tables, the same defect class removed
from the engine as CANON_VERSION 2. Semantic-identity hashing
(hash.compute_text_hash) still normalizes deliberately — "is this the
same text" is a different question from "are these the same bytes".

Mirror implementation: typescript/src/canonical.ts.
"""
from __future__ import annotations

import math
from typing import Any


def _utf16_codeunits(s: str) -> list[int]:
    """Return the UTF-16 code units of `s` (BMP = 1 unit, supplementary = 2)."""
    out: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp <= 0xFFFF:
            out.append(cp)
        else:
            cp -= 0x10000
            out.append(0xD800 + (cp >> 10))
            out.append(0xDC00 + (cp & 0x3FF))
    return out


def _utf16_key(s: str) -> tuple[int, ...]:
    return tuple(_utf16_codeunits(s))


def _escape_string(s: str) -> str:
    """RFC 8785 / RFC 8259 string escaping with \\uXXXX for non-ASCII.

    - NO normalization: the string is escaped exactly as parsed (see the
      module docstring's correction note — NFC here broke verification
      under the published er1-verify for any non-NFC-invariant string).
    - Mandatory escapes: \" \\ and U+0000..U+001F.
    - All other ASCII printable (0x20..0x7E except \" \\) emitted verbatim.
    - All non-ASCII emitted as \\uXXXX (lowercase hex). Supplementary
      planes use surrogate pairs.
    """
    out: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        elif cp < 0x7F:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append(f"\\u{cp:04x}")
        else:
            # Supplementary plane — surrogate pair
            v = cp - 0x10000
            hi = 0xD800 + (v >> 10)
            lo = 0xDC00 + (v & 0x3FF)
            out.append(f"\\u{hi:04x}\\u{lo:04x}")
    out.append('"')
    return "".join(out)


# The integers both languages represent exactly. Beyond this a JS Number loses
# precision and its ToString stops being a faithful integer, so it is refused rather
# than emitted in a form a conforming verifier would read differently.
MAX_SAFE_INT = 2 ** 53 - 1


def _format_number(n: int | float) -> str:
    """Integers only, and only those exactly representable in both Python and ECMAScript.

    This USED TO emit non-integer floats via a hand-rolled repr-to-ECMAScript normaliser,
    and it was WRONG in the one direction that breaks the product: `1e20` came out `1e20`
    where ECMAScript ToString yields `1e+20`, `1e16` came out `1e16` where ToString yields
    `10000000000000000`, so the producer signed a receipt whose canonical bytes no
    RFC-8785-conforming verifier reproduces — and the PUBLISHED `er1_verify` refuses floats
    outright, so a receipt carrying one recomputed as malformed on the very verifier a
    stranger runs. A producer that mints what the spec's verifier rejects has broken the
    only promise the receipt makes.

    The fix is not a better float formatter (RFC 8785 defers to the full ECMAScript
    Number::toString / Ryū algorithm, and a second hand-rolled copy is a second thing to
    drift). It is to emit exactly what every verifier already accepts — integers — and to
    refuse everything else at mint time, the same rule and the same shape as
    `er1_verify._number`. Zero receipts in the corpus or the golden vectors carry a
    non-integer number, so nothing legitimate is lost; a float now fails loudly at
    production instead of silently at a stranger's verifier."""
    if isinstance(n, bool):  # bool is a subclass of int in Python
        return "true" if n else "false"
    if isinstance(n, int):
        if abs(n) > MAX_SAFE_INT:
            raise ValueError(
                f"integer {n} is outside the exactly-representable range (|n| <= 2**53-1) "
                "and cannot be canonicalized identically across implementations")
        return str(n)
    if isinstance(n, float):
        # +0.0 and -0.0 both land here as integer-valued and emit "0".
        if n.is_integer() and abs(n) <= MAX_SAFE_INT:
            return str(int(n))
        raise ValueError(
            f"non-integral number {n} is not canonicalizable (integers only): emitting a "
            "float in a per-language format lets two conforming verifiers disagree on the "
            "canonical bytes, and a disagreement about bytes is a disagreement about tamper")
    raise TypeError(f"Unsupported numeric type: {type(n)}")


def _canonical(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_number(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, dict):
        # sort keys by utf-16 code unit order (matches JS Array.sort default)
        keys = sorted(value.keys(), key=_utf16_key)
        parts = []
        for k in keys:
            if not isinstance(k, str):
                raise TypeError(f"Object keys must be strings, got {type(k)}")
            parts.append(_escape_string(k) + ":" + _canonical(value[k]))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    # BaseModel / dataclass — caller should have dumped to dict first.
    raise TypeError(f"Cannot canonicalize value of type {type(value)}")


def canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 byte string of `value`.

    `value` is typically a Receipt model dumped via `model.model_dump()`
    or a plain dict. This function does NOT accept Pydantic instances
    directly — callers should `.model_dump(mode='python')` first to
    avoid silent coercions.
    """
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    return _canonical(value).encode("utf-8")
