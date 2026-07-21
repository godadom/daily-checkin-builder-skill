"""Account-isolated authentication state and optional bounded refresh hooks."""

from __future__ import annotations

from http.cookies import CookieError, SimpleCookie
from typing import Callable, Protocol, TYPE_CHECKING

from .models import AccountConfig

if TYPE_CHECKING:
    from .client import HttpResponse


RefreshCallback = Callable[[AccountConfig], str | None]


class AuthProvider(Protocol):
    """Site-specific authentication adapter used by one account only."""

    def headers(self) -> dict[str, str]: ...

    def observe(self, response: "HttpResponse") -> None: ...

    def refresh(self) -> bool: ...


class AccountAuthProvider:
    """Static bearer/API-key auth plus a small per-account cookie jar.

    A generated site integration may inject one documented refresh callback.
    The default provider never performs login or invents a refresh endpoint.
    """

    def __init__(self, account: AccountConfig, refresh_callback: RefreshCallback | None = None):
        self.account = account
        self._secret = account.secret
        self._refresh_callback = refresh_callback
        self._refresh_attempted = False
        self._cookies: dict[str, str] = {}
        if account.auth_type == "cookie":
            self._replace_cookies(account.secret)

    def _replace_cookies(self, value: str) -> None:
        parsed = SimpleCookie()
        try:
            parsed.load(value)
        except CookieError:
            parsed = SimpleCookie()
        self._cookies = {name: morsel.value for name, morsel in parsed.items()}
        if not self._cookies:
            raw = value.split("=", 1)
            if len(raw) == 2 and raw[0].strip():
                self._cookies[raw[0].strip()] = raw[1]
            elif value:
                self._cookies[self.account.cookie_name] = value

    def headers(self) -> dict[str, str]:
        if self.account.auth_type == "bearer":
            return {"Authorization": f"Bearer {self._secret}"}
        if self.account.auth_type == "cookie":
            value = "; ".join(f"{name}={secret}" for name, secret in self._cookies.items())
            return {"Cookie": value}
        if self.account.auth_type == "api_key":
            return {self.account.api_key_header: self._secret}
        raise ValueError("unsupported validated auth type")

    def observe(self, response: "HttpResponse") -> None:
        if self.account.auth_type != "cookie":
            return
        for header in response.header_values("Set-Cookie"):
            parsed = SimpleCookie()
            try:
                parsed.load(header)
            except CookieError:
                continue
            for name, morsel in parsed.items():
                if not morsel.value or morsel["max-age"] == "0":
                    self._cookies.pop(name, None)
                else:
                    self._cookies[name] = morsel.value

    def refresh(self) -> bool:
        if self._refresh_attempted or self._refresh_callback is None:
            return False
        self._refresh_attempted = True
        refreshed = self._refresh_callback(self.account)
        if not isinstance(refreshed, str) or refreshed == "":
            return False
        self._secret = refreshed
        if self.account.auth_type == "cookie":
            self._replace_cookies(refreshed)
        return True


def build_auth_provider(
    account: AccountConfig,
    refresh_callback: RefreshCallback | None = None,
) -> AccountAuthProvider:
    return AccountAuthProvider(account, refresh_callback)


def authentication_headers(account: AccountConfig) -> dict[str, str]:
    """Compatibility helper for callers that do not need session updates."""

    return build_auth_provider(account).headers()
