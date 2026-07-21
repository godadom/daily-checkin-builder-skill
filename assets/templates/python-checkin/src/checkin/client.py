"""Small HTTP client with bounded, method-aware retries."""

from __future__ import annotations

import email.utils
import http.client
import json
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable, Mapping, Protocol
from urllib.parse import urlsplit


CHALLENGE_MARKERS = (
    b"captcha",
    b"turnstile",
    b"recaptcha",
    b"hcaptcha",
    b"webauthn",
    b"device_verification_required",
    b"sms_required",
    b"otp_required",
    b"mfa_required",
    b"security_verification_required",
    b"just a moment",
    b"cf-chl",
    b"waf challenge",
    b"verify you are human",
)
MAX_RESPONSE_BYTES = 1_048_576
MAX_RETRY_DELAY_SECONDS = 60.0


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    attempts: int = 1
    header_items: tuple[tuple[str, str], ...] = ()

    def json(self) -> object:
        return json.loads(self.body.decode("utf-8"))

    def header_values(self, name: str) -> tuple[str, ...]:
        values = tuple(
            value for key, value in self.header_items if key.casefold() == name.casefold()
        )
        if values:
            return values
        fallback = _header(self, name)
        return (fallback,) if fallback else ()


class NetworkError(RuntimeError):
    def __init__(self, message: str, *, attempts: int = 1):
        super().__init__(message)
        self.attempts = attempts


class ResponseTooLarge(RuntimeError):
    """Raised without retaining the response body when its safe cap is exceeded."""


def read_bounded(response: http.client.HTTPResponse) -> bytes:
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ResponseTooLarge("HTTP response exceeded the configured safe size limit")
    return body


def _header(response: HttpResponse, name: str) -> str:
    return next((value for key, value in response.headers.items() if key.casefold() == name.casefold()), "")


def is_html_response(response: HttpResponse) -> bool:
    """Return whether an API response is HTML and therefore not retry-safe."""

    content_type = _header(response, "Content-Type").casefold()
    prefix = response.body[:256].lstrip().lower()
    return "text/html" in content_type or prefix.startswith((b"<!doctype html", b"<html"))


def is_security_challenge(response: HttpResponse) -> bool:
    """Recognize a bounded set of challenge signals without trying to bypass them."""

    if _header(response, "X-Security-Challenge"):
        return True
    if "challenge" in _header(response, "CF-Mitigated").casefold():
        return True
    sample = response.body[:8192].lower()
    return any(marker in sample for marker in CHALLENGE_MARKERS)


class Transport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
    ) -> HttpResponse: ...


class StdlibTransport:
    """HTTPS transport with separate connection and response-read timeouts."""

    def request(self, method, url, headers, body, connect_timeout, read_timeout) -> HttpResponse:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise NetworkError("only HTTPS requests are supported")
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=connect_timeout)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            connection.request(method, path, body=body, headers=dict(headers))
            if connection.sock is not None:
                connection.sock.settimeout(read_timeout)
            response = connection.getresponse()
            header_items = tuple(response.getheaders())
            return HttpResponse(
                response.status,
                dict(header_items),
                read_bounded(response),
                header_items=header_items,
            )
        finally:
            connection.close()


class ReliableHttpClient:
    RETRYABLE = {429, 500, 502, 503, 504}

    def __init__(
        self,
        transport: Transport | None = None,
        *,
        connect_timeout: float = 5,
        read_timeout: float = 15,
        max_retries: int = 2,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.transport = transport or StdlibTransport()
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_retries = max_retries
        self.sleeper = sleeper

    @staticmethod
    def _retry_after(headers: Mapping[str, str], fallback: float) -> float | None:
        value = next((v for k, v in headers.items() if k.lower() == "retry-after"), "")
        if value.isdigit():
            delay = float(value)
            return delay if delay <= MAX_RETRY_DELAY_SECONDS else None
        if value:
            try:
                when = email.utils.parsedate_to_datetime(value)
                delay = max((when - datetime.now(timezone.utc)).total_seconds(), 0.0)
                return delay if delay <= MAX_RETRY_DELAY_SECONDS else None
            except (TypeError, ValueError, OverflowError):
                pass
        return fallback

    def retry_delay(self, response: HttpResponse, fallback: float = 1.0) -> float | None:
        return self._retry_after(response.headers, fallback)

    def sleep(self, seconds: float) -> None:
        self.sleeper(seconds)

    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None = None, *, idempotent: bool = False) -> HttpResponse:
        method = method.upper()
        may_retry = method in {"GET", "HEAD", "OPTIONS"} or idempotent
        attempts = self.max_retries + 1 if may_retry else 1
        for attempt in range(attempts):
            try:
                response = self.transport.request(method, url, headers, body, self.connect_timeout, self.read_timeout)
            except ResponseTooLarge:
                # A structurally unexpected response is not a transient
                # transport failure and must not trigger repeated downloads.
                raise
            except (OSError, TimeoutError, NetworkError) as exc:
                if attempt + 1 >= attempts:
                    raise NetworkError("HTTP request failed after bounded retries", attempts=attempt + 1) from exc
                self.sleeper(min(2**attempt, 30))
                continue
            # API calls expect JSON. Retrying HTML can repeatedly hit a WAF or
            # an unrecognized interstitial, so return it to the state machine
            # for fail-closed classification after the first request.
            if is_html_response(response) or is_security_challenge(response):
                return replace(response, attempts=attempt + 1)
            if response.status not in self.RETRYABLE or attempt + 1 >= attempts:
                return replace(response, attempts=attempt + 1)
            delay = self._retry_after(response.headers, min(2**attempt, 30))
            if delay is None:
                return replace(response, attempts=attempt + 1)
            self.sleeper(delay)
        raise AssertionError("unreachable")
