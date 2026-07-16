"""Notification boundary; default implementation deliberately logs only."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from .models import CheckinResult


def notify(results: Sequence[CheckinResult], logger: logging.Logger) -> None:
    succeeded = sum(result.ok for result in results)
    logger.info("check-in summary: %d/%d accounts succeeded", succeeded, len(results))
