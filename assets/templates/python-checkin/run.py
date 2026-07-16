"""Portable entry point for local shells, GitHub Actions, and QingLong."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from checkin.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
