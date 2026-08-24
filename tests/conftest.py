"""Every test runs with sockets blocked — verification is offline, enforced.

A test that needs the network would need an explicit `network` marker; none
in this suite carries one, and that absence is the point.
"""
from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(request, monkeypatch):
    if request.node.get_closest_marker("network"):
        return

    def _blocked(*_a, **_k):
        raise RuntimeError("network blocked: verification is offline forever")

    monkeypatch.setattr(socket, "socket", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "socketpair", _blocked, raising=False)
