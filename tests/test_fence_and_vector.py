"""The fence is schema, and the schema refuses.

An inversion event without the exact fence bytes is refused; the lexicon
fires on accusation vocabulary anywhere except the canonical disclaimer that
names what it denies; and the vector's share arithmetic is integer-exact.
"""
from __future__ import annotations

import pytest

from campanile.fence import BANNED, scan_bytes
from campanile.vector import (FENCE_FIELDS, WHAT_THIS_IS_NOT, _share_e6,
                              require_fence)


def test_fence_fields_required_exactly():
    good = {**FENCE_FIELDS, "class": "tests", "chain_index": 1,
            "date": "2024-01-01", "sha": "f" * 40}
    require_fence(good)
    for k in FENCE_FIELDS:
        broken = dict(good)
        broken[k] = "reworded"
        with pytest.raises(ValueError):
            require_fence(broken)
        del broken[k]
        with pytest.raises(ValueError):
            require_fence(broken)


def test_lexicon_fires_outside_the_canonical_disclaimer():
    for word in BANNED:
        assert scan_bytes(f"a {word} walked in".encode()) == [word]
    # the canonical disclaimer itself is exempt — exact bytes only
    assert scan_bytes(WHAT_THIS_IS_NOT.encode()) == []
    assert scan_bytes((WHAT_THIS_IS_NOT + " but a compromise").encode()) \
        == ["compromise"]


def test_share_e6_is_integer_floor_arithmetic():
    assert _share_e6({0: 1}, 0, 3) == 333333
    assert _share_e6({0: 2}, 0, 3) == 666666
    assert _share_e6({}, 0, 3) == 0
    assert _share_e6({0: 5}, 0, 0) == 5_000_000  # max(total,1) guard
