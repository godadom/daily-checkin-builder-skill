"""Site-adapted interactive login state machine with secret-safe boundaries."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit


ACCOUNT_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
COOKIE_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
MAX_COOKIE_VALUE_LENGTH = 16_384


class LoginState(str, Enum):
    WAITING_FOR_CREDENTIALS = "WAITING_FOR_CREDENTIALS"
    WAITING_FOR_OTP = "WAITING_FOR_OTP"
    WAITING_FOR_CHALLENGE = "WAITING_FOR_CHALLENGE"
    SUCCESS = "SUCCESS"
    REJECTED = "REJECTED"
    TIMEOUT = "TIMEOUT"
    SITE_CHANGED = "SITE_CHANGED"
    STORAGE_ERROR = "STORAGE_ERROR"
    LOGIN_UI_UNAVAILABLE = "LOGIN_UI_UNAVAILABLE"


WAITING_STATES = frozenset(
    {
        LoginState.WAITING_FOR_CREDENTIALS,
        LoginState.WAITING_FOR_OTP,
        LoginState.WAITING_FOR_CHALLENGE,
    }
)
TERMINAL_BROWSER_STATES = frozenset(
    {
        LoginState.SUCCESS,
        LoginState.REJECTED,
        LoginState.SITE_CHANGED,
        LoginState.LOGIN_UI_UNAVAILABLE,
    }
)
SAFE_MESSAGES = {
    LoginState.WAITING_FOR_CREDENTIALS: "waiting for credentials in the visible login page",
    LoginState.WAITING_FOR_OTP: "waiting for the operator to enter the one-time code",
    LoginState.WAITING_FOR_CHALLENGE: "waiting for the operator to complete the site challenge",
    LoginState.SUCCESS: "login session saved",
    LoginState.REJECTED: "the site rejected or the operator cancelled the login",
    LoginState.TIMEOUT: "interactive login timed out",
    LoginState.SITE_CHANGED: "the verified login contract no longer matches",
    LoginState.STORAGE_ERROR: "login succeeded but protected storage failed",
    LoginState.LOGIN_UI_UNAVAILABLE: "a secure visible login session is unavailable",
}


@dataclass(frozen=True, repr=False)
class LoginCredentials:
    """Optional credentials used only for protected, site-specific autofill."""

    username: str
    password: str

    def __repr__(self) -> str:
        return "LoginCredentials(username=[REDACTED], password=[REDACTED])"


@dataclass(frozen=True)
class LoginObservation:
    state: LoginState


@dataclass(frozen=True)
class LoginResult:
    account_alias: str
    state: LoginState
    message: str
    stored: bool = False


class VisibleLoginSession(Protocol):
    """Site-specific headed browser adapter backed by one stable context."""

    def start(self, credentials: LoginCredentials | None) -> None: ...

    def observe(self) -> LoginObservation: ...

    def read_cookies(self, allowed_origins: Sequence[str]) -> Mapping[str, str]: ...

    def close(self) -> None: ...


class CookieSecretStore(Protocol):
    """Selected platform adapter; implementations must not log secret values."""

    def save_cookie(self, account_alias: str, cookie_header: str) -> None: ...


StatePresenter = Callable[[LoginState, str], None]
Clock = Callable[[], float]
Waiter = Callable[[float], None]


class InteractiveLoginRunner:
    """Drive one manual login without automating OTP or challenge interaction."""

    def __init__(
        self,
        session: VisibleLoginSession,
        store: CookieSecretStore,
        *,
        allowed_origins: Sequence[str],
        required_cookie_names: Sequence[str],
        timeout_seconds: float = 300,
        poll_seconds: float = 1,
        presenter: StatePresenter | None = None,
        clock: Clock = time.monotonic,
        wait: Waiter = time.sleep,
    ):
        if not allowed_origins:
            raise ValueError("interactive login requires at least one allowed origin")
        if not required_cookie_names:
            raise ValueError("interactive login requires a Cookie-name whitelist")
        if timeout_seconds <= 0 or poll_seconds <= 0:
            raise ValueError("interactive login timeout and polling must be positive")
        names = tuple(required_cookie_names)
        if len(names) != len(set(names)) or not all(COOKIE_NAME_RE.fullmatch(name) for name in names):
            raise ValueError("interactive login Cookie names must be unique HTTP tokens")
        origins = tuple(allowed_origins)
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("interactive login origins must be HTTPS origins without credentials or paths")
        self._session = session
        self._store = store
        self._allowed_origins = origins
        self._required_cookie_names = names
        self._timeout_seconds = timeout_seconds
        self._poll_seconds = poll_seconds
        self._presenter = presenter or (lambda state, message: None)
        self._clock = clock
        self._wait = wait

    def run(
        self,
        account_alias: str,
        credentials: LoginCredentials | None = None,
    ) -> LoginResult:
        if not ACCOUNT_ALIAS_RE.fullmatch(account_alias):
            return self._result(account_alias, LoginState.SITE_CHANGED)
        deadline = self._clock() + self._timeout_seconds
        announced_state: LoginState | None = None
        try:
            try:
                self._session.start(credentials)
            except Exception:
                return self._result(account_alias, LoginState.LOGIN_UI_UNAVAILABLE)
            credentials = None

            while self._clock() < deadline:
                try:
                    observation = self._session.observe()
                except Exception:
                    return self._result(account_alias, LoginState.SITE_CHANGED)
                state = observation.state
                if state not in WAITING_STATES | TERMINAL_BROWSER_STATES:
                    return self._result(account_alias, LoginState.SITE_CHANGED)
                if state in WAITING_STATES:
                    if state != announced_state:
                        self._presenter(state, SAFE_MESSAGES[state])
                        announced_state = state
                    self._wait(self._poll_seconds)
                    continue
                if state != LoginState.SUCCESS:
                    return self._result(account_alias, state)
                return self._save_success(account_alias)
            return self._result(account_alias, LoginState.TIMEOUT)
        finally:
            credentials = None
            try:
                self._session.close()
            except Exception:
                pass

    def _save_success(self, account_alias: str) -> LoginResult:
        try:
            observed = self._session.read_cookies(self._allowed_origins)
        except Exception:
            return self._result(account_alias, LoginState.SITE_CHANGED)
        cookie_parts: list[str] = []
        for name in self._required_cookie_names:
            value = observed.get(name)
            if (
                not isinstance(value, str)
                or value == ""
                or len(value) > MAX_COOKIE_VALUE_LENGTH
                or any(
                    character == ";" or ord(character) < 32 or ord(character) == 127
                    for character in value
                )
            ):
                return self._result(account_alias, LoginState.SITE_CHANGED)
            cookie_parts.append(f"{name}={value}")
        serialized_header = "; ".join(cookie_parts)
        try:
            self._store.save_cookie(account_alias, serialized_header)
        except Exception:
            return self._result(account_alias, LoginState.STORAGE_ERROR)
        return self._result(account_alias, LoginState.SUCCESS, stored=True)

    @staticmethod
    def _result(account_alias: str, state: LoginState, stored: bool = False) -> LoginResult:
        safe_alias = account_alias if ACCOUNT_ALIAS_RE.fullmatch(account_alias) else "invalid-account"
        return LoginResult(safe_alias, state, SAFE_MESSAGES[state], stored)
