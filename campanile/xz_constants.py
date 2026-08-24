"""xz_constants — the calibration case's frozen incident constants.

Derived by the generator from the frozen calibration method; the
hindsight overlay is PER-INCIDENT ONLY and never applies to any other
repo (custody.py's OverlaySpec doctrine).
"""
from __future__ import annotations

XZ_PIN = 'c8b8ab2ef1eb0a0217ad2027d7f5d242ceb944d3'
DISCLOSURE_DATE = '2024-03-29'
OVERLAY_PATHS = ('tests/files/bad-3-corrupt_lzma2.xz', 'tests/files/good-large_compressed.lzma', 'CMakeLists.txt')
OVERLAY_WINDOW = ('2024-01-01', '2024-04-01')
TARBALL_ONLY_PATH = 'm4/build-to-host.m4'
