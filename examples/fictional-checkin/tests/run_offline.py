#!/usr/bin/env python3
"""Install a process-wide socket deny hook before discovering offline tests."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path


TESTS = Path(__file__).resolve().parent


def deny_live_network(*args, **kwargs):
    raise AssertionError("offline tests must not open sockets")


def deny_socket_audit_events(event, args):
    if event.startswith("socket."):
        raise AssertionError("offline tests must not open sockets")


def main() -> int:
    socket.create_connection = deny_live_network
    sys.addaudithook(deny_socket_audit_events)
    suite = unittest.defaultTestLoader.discover(
        start_dir=str(TESTS),
        pattern="test*.py",
        top_level_dir=str(TESTS),
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
