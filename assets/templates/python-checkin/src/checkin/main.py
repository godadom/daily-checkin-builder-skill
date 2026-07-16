"""Shared local, GitHub Actions, and QingLong entry point."""

from __future__ import annotations

import random
import sys
import time
from collections.abc import Callable, Sequence
from datetime import datetime
from zoneinfo import ZoneInfo

from .client import ReliableHttpClient
from .config import ConfigError, Settings, load_settings
from .logging_utils import configure_logging, safe_json
from .models import AccountConfig, CheckinResult, CheckinStatus, RunSummary
from .notifier import notify
from .service import CheckinService


def execute_accounts(accounts: Sequence[AccountConfig], runner: Callable[[AccountConfig], CheckinResult]) -> RunSummary:
    results: list[CheckinResult] = []
    for account in accounts:
        try:
            results.append(runner(account))
        except Exception:
            results.append(CheckinResult(account.name, CheckinStatus.INTERNAL_ERROR, "unclassified internal account error"))
    return RunSummary.from_results(results)


def run(settings: Settings) -> int:
    secrets = [account.secret for account in settings.accounts]
    fields = [field for account in settings.accounts for field in account.sensitive_fields]
    logger = configure_logging(secrets, fields)
    run_time = datetime.now(ZoneInfo(settings.timezone))
    logger.info("run_date=%s timezone=%s", run_time.date().isoformat(), settings.timezone)
    if settings.jitter_max_seconds:
        delay = random.SystemRandom().uniform(0, settings.jitter_max_seconds)
        logger.info("applying configured schedule jitter: %.1f seconds", delay)
        time.sleep(delay)
    client = ReliableHttpClient(connect_timeout=settings.connect_timeout, read_timeout=settings.read_timeout, max_retries=settings.max_retries)
    service = CheckinService(settings, client)
    summary = execute_accounts(settings.accounts, service.check_in)
    for result in summary.results:
        logger.info("result=%s", safe_json({"account": result.account, "status": result.status.value, "message": result.message, "details": result.details, "attempts": result.attempts, "retried": result.retried, "retry_recommended": result.retry_recommended}, secret_values=secrets, sensitive_fields=fields))
    logger.info("status_counts=%s exit_code=%d", safe_json(summary.status_counts), summary.exit_code)
    if settings.notify_mode == "log":
        try:
            notify(summary.results, logger)
        except Exception:
            logger.error("notification failed with a redacted internal error")
    return summary.exit_code


def main() -> int:
    try:
        return run(load_settings())
    except ConfigError as exc:
        configure_logging().error("configuration error: %s", exc)
        return 2
    except Exception:
        configure_logging().error("unclassified internal error")
        return 70


if __name__ == "__main__":
    sys.exit(main())
