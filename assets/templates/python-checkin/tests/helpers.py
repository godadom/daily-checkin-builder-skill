from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def deny_live_network(*args, **kwargs):
    raise AssertionError("offline tests must not open sockets")


from checkin.client import HttpResponse, ReliableHttpClient  # noqa: E402
from checkin.config import Settings  # noqa: E402
from checkin.models import AccountConfig  # noqa: E402
from checkin.service import CheckinService  # noqa: E402

socket.create_connection = deny_live_network


class QueueTransport:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def request(self, method, url, headers, body, connect_timeout, read_timeout):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body, "timeouts": (connect_timeout, read_timeout)})
        if not self.outcomes:
            raise AssertionError("mock transport received an unexpected request")
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def fixture(name: str, status: int = 200, headers=None) -> HttpResponse:
    body = (ROOT / "tests" / "fixtures" / name).read_bytes()
    return HttpResponse(status, headers or {"Content-Type": "application/json"}, body)


def response(payload, status=200, headers=None) -> HttpResponse:
    return HttpResponse(status, headers or {"Content-Type": "application/json"}, json.dumps(payload).encode())


def account(name="alice", secret="placeholder-test-token") -> AccountConfig:
    return AccountConfig(name, "bearer", secret)


def settings(accounts=None) -> Settings:
    return Settings("https://checkin.example.invalid", "/api/checkin/status", "/api/checkin", tuple(accounts or [account()]), max_retries=2)


def service(*outcomes, accounts=None, auth_provider_factory=None):
    transport = QueueTransport(*outcomes)
    client = ReliableHttpClient(transport, max_retries=2, sleeper=lambda _: None)
    options = {"auth_provider_factory": auth_provider_factory} if auth_provider_factory else {}
    return CheckinService(settings(accounts), client, **options), transport
