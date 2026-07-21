"""Domain models shared by configuration, service, and entry points."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class CheckinStatus(str, Enum):
    SUCCESS = "SUCCESS"
    ALREADY_DONE = "ALREADY_DONE"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    ACCESS_DENIED = "ACCESS_DENIED"
    TEMPORARY_ERROR = "TEMPORARY_ERROR"
    SITE_CHANGED = "SITE_CHANGED"
    CONFIG_ERROR = "CONFIG_ERROR"
    UNSUPPORTED_SECURITY_CHALLENGE = "UNSUPPORTED_SECURITY_CHALLENGE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


EXIT_PRIORITY: tuple[tuple[CheckinStatus, int], ...] = (
    (CheckinStatus.ACCESS_DENIED, 7),
    (CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE, 6),
    (CheckinStatus.CONFIG_ERROR, 2),
    (CheckinStatus.SITE_CHANGED, 5),
    (CheckinStatus.AUTH_EXPIRED, 3),
    (CheckinStatus.TEMPORARY_ERROR, 4),
    (CheckinStatus.INTERNAL_ERROR, 70),
)


@dataclass(frozen=True)
class AccountConfig:
    name: str
    auth_type: str
    secret: str = field(repr=False)
    cookie_name: str = "session"
    api_key_header: str = "X-API-Key"
    sensitive_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class CheckinResult:
    account: str
    status: CheckinStatus
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.status in {CheckinStatus.SUCCESS, CheckinStatus.ALREADY_DONE}

    @property
    def retried(self) -> bool:
        return self.attempts > 1

    @property
    def retry_recommended(self) -> bool:
        return self.status is CheckinStatus.TEMPORARY_ERROR


@dataclass(frozen=True)
class RunSummary:
    results: tuple[CheckinResult, ...]

    @classmethod
    def from_results(cls, results: list[CheckinResult] | tuple[CheckinResult, ...]) -> "RunSummary":
        return cls(tuple(results))

    @property
    def status_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CheckinStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def exit_code(self) -> int:
        present = {result.status for result in self.results}
        for status, code in EXIT_PRIORITY:
            if status in present:
                return code
        return 0
