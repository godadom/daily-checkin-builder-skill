"""Business state machine for status query, check-in, and verification."""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from .auth import AuthProvider, build_auth_provider
from .client import (
    HttpResponse,
    NetworkError,
    ReliableHttpClient,
    ResponseTooLarge,
    is_html_response,
    is_security_challenge,
)
from .config import Settings
from .models import AccountConfig, CheckinResult, CheckinStatus


class CheckinService:
    AUTH_CODES = {"auth_expired", "invalid_token", "unauthorized", "csrf_invalid"}
    ACCESS_DENIED_CODES = {"forbidden", "permission_denied", "access_denied"}

    def __init__(
        self,
        settings: Settings,
        client: ReliableHttpClient,
        auth_provider_factory: Callable[[AccountConfig], AuthProvider] = build_auth_provider,
    ):
        self.settings = settings
        self.client = client
        self.auth_provider_factory = auth_provider_factory
        self.auth_providers = {
            account: auth_provider_factory(account) for account in settings.accounts
        }

    def _auth(self, account: AccountConfig) -> AuthProvider:
        provider = self.auth_providers.get(account)
        if provider is None:
            provider = self.auth_provider_factory(account)
            self.auth_providers[account] = provider
        return provider

    def _headers(self, account: AccountConfig) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": self.settings.user_agent,
            **self._auth(account).headers(),
        }

    def _request(
        self,
        account: AccountConfig,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> HttpResponse:
        response = self.client.request(method, url, headers, body)
        self._auth(account).observe(response)
        return response

    @staticmethod
    def _payload(response: HttpResponse) -> Mapping[str, Any] | None:
        try:
            value = response.json()
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _challenge(response: HttpResponse, payload: Mapping[str, Any] | None) -> bool:
        return is_security_challenge(response) or bool(
            payload
            and payload.get("code")
            in {
                "captcha_required", "webauthn_required", "device_verification_required",
                "sms_required", "otp_required", "mfa_required", "security_verification_required",
            }
        )

    def _query(
        self,
        account: AccountConfig,
        *,
        allow_refresh: bool = True,
    ) -> tuple[CheckinResult | None, str | None, bool]:
        try:
            response = self._request(
                account,
                "GET",
                self.settings.base_url + self.settings.status_path,
                self._headers(account),
            )
        except ResponseTooLarge:
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "status response exceeded the safe size limit"), None, False
        except NetworkError as exc:
            return CheckinResult(account.name, CheckinStatus.TEMPORARY_ERROR, "status query timed out or failed", attempts=exc.attempts), None, False
        payload = self._payload(response)
        if self._challenge(response, payload):
            return CheckinResult(account.name, CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE, "manual security challenge required"), None, False
        code = payload.get("code") if payload else None
        if response.status == 401 or code in self.AUTH_CODES:
            if allow_refresh and self._auth(account).refresh():
                return self._query(account, allow_refresh=False)
            return CheckinResult(account.name, CheckinStatus.AUTH_EXPIRED, "authentication rejected"), None, False
        if response.status == 403:
            if code in self.ACCESS_DENIED_CODES:
                return CheckinResult(account.name, CheckinStatus.ACCESS_DENIED, "server denied account permission; do not retry or bypass"), None, False
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "unclassified HTTP 403; review sanitized evidence"), None, False
        if is_html_response(response):
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "status endpoint returned unexpected HTML; review sanitized evidence", attempts=response.attempts), None, False
        if response.status == 429 or response.status >= 500:
            return CheckinResult(account.name, CheckinStatus.TEMPORARY_ERROR, f"status endpoint returned HTTP {response.status}", attempts=response.attempts), None, False
        if (
            response.status != 200
            or payload is None
            or type(payload.get("code")) is not int
            or payload.get("code") != 0
        ):
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "unexpected status response"), None, False
        data = payload.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("checked_in"), bool):
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "status response schema changed"), None, False
        if data["checked_in"]:
            return CheckinResult(account.name, CheckinStatus.ALREADY_DONE, "already checked in today"), None, True
        csrf = data.get("csrf_token")
        if (
            not isinstance(csrf, str)
            or not csrf
            or len(csrf) > 4096
            or any(not 33 <= ord(character) <= 126 for character in csrf)
        ):
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "CSRF token missing from status response"), None, False
        return None, csrf, False

    def _confirm_after_ambiguous(self, account: AccountConfig) -> CheckinResult:
        result, _, checked = self._query(account)
        if checked:
            return CheckinResult(account.name, CheckinStatus.SUCCESS, "check-in confirmed after ambiguous response")
        if result and result.status in {
            CheckinStatus.AUTH_EXPIRED,
            CheckinStatus.ACCESS_DENIED,
            CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE,
            CheckinStatus.SITE_CHANGED,
        }:
            return result
        return CheckinResult(account.name, CheckinStatus.TEMPORARY_ERROR, "check-in outcome is not confirmed; POST was not repeated")

    def check_in(self, account: AccountConfig) -> CheckinResult:
        before, csrf, _ = self._query(account)
        if before is not None:
            return before
        headers = {**self._headers(account), "Content-Type": "application/json", "X-CSRF-Token": csrf or ""}
        body = json.dumps({"csrf_token": csrf}, separators=(",", ":")).encode("utf-8")
        try:
            response = self._request(
                account,
                "POST",
                self.settings.base_url + self.settings.checkin_path,
                headers,
                body,
            )
        except ResponseTooLarge:
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "check-in response exceeded the safe size limit")
        except NetworkError:
            return self._confirm_after_ambiguous(account)
        payload = self._payload(response)
        if self._challenge(response, payload):
            return CheckinResult(account.name, CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE, "manual security challenge required")
        if response.status == 429:
            delay = self.client.retry_delay(response)
            if delay is None:
                return CheckinResult(account.name, CheckinStatus.TEMPORARY_ERROR, "rate-limit window exceeds the safe wait cap; POST was not repeated", attempts=response.attempts)
            self.client.sleep(delay)
            return self._confirm_after_ambiguous(account)
        if response.status >= 500:
            if any(key.casefold() == "retry-after" for key in response.headers):
                delay = self.client.retry_delay(response)
                if delay is None:
                    return CheckinResult(account.name, CheckinStatus.TEMPORARY_ERROR, "server wait window exceeds the safe cap; POST was not repeated", attempts=response.attempts)
                self.client.sleep(delay)
            return self._confirm_after_ambiguous(account)
        code = payload.get("code") if payload else None
        if response.status == 401 or code in self.AUTH_CODES:
            if self._auth(account).refresh():
                return self._confirm_after_ambiguous(account)
            return CheckinResult(account.name, CheckinStatus.AUTH_EXPIRED, "authentication or CSRF token expired")
        if response.status == 403:
            if code in self.ACCESS_DENIED_CODES:
                return CheckinResult(account.name, CheckinStatus.ACCESS_DENIED, "server denied account permission; do not retry or bypass")
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "unclassified HTTP 403; review sanitized evidence")
        if is_html_response(response):
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "check-in endpoint returned unexpected HTML; review sanitized evidence", attempts=response.attempts)
        if payload is None:
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "unexpected check-in response")
        code = payload.get("code")
        if code == "already_checked":
            return CheckinResult(account.name, CheckinStatus.ALREADY_DONE, "already checked in today")
        if response.status != 200:
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, f"unexpected check-in HTTP {response.status}")
        data = payload.get("data")
        if type(code) is not int or code != 0 or not isinstance(data, dict) or data.get("checked_in") is not True:
            return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "business response did not confirm check-in")
        details: dict[str, int | float] = {}
        if "points_delta" in data:
            points_delta = data["points_delta"]
            if isinstance(points_delta, bool) or not isinstance(points_delta, (int, float)):
                return CheckinResult(account.name, CheckinStatus.SITE_CHANGED, "points delta changed type")
            details["points_delta"] = points_delta
        return CheckinResult(account.name, CheckinStatus.SUCCESS, "check-in succeeded", details)
