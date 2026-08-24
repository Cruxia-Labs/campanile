"""campanile — replay a repository's git history; report its custody structure.

The instrument reads only the STRUCTURE of recorded diffs (hunk arithmetic,
paths, author strings — content lines are consumed by count, never inspected)
and reports which author strings held which file classes, and when that
structure shifted. Verification is offline, deterministic, and model-free;
every claim in this package resolves to a runnable check in tests/.

    campanile replay xz          # the calibration case, offline, from the
                                 # shipped structural fixture
    campanile scan [PATH]        # your own repository's custody vector
    campanile verify PATH        # a receipt, vector, or fixture manifest

What a custody inversion is — and is not — travels as SCHEMA in every event
object (vector.py): structural measurement, never an accusation.
"""

__version__ = "1.0.0.dev0"
