"""Parse and validate environment-only configuration."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import AccountConfig


class ConfigError(ValueError):
    """Raised for actionable, non-secret configuration errors."""


ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PHONE_ALIAS_RE = re.compile(r"^(?:1[3-9]\d{9}|\d{10,15})$")
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
SENSITIVE_FIELD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*$")
MAX_ACCOUNTS = 50


@dataclass(frozen=True)
class Settings:
    base_url: str
    status_path: str
    checkin_path: str
    accounts: tuple[AccountConfig, ...]
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    max_retries: int = 2
    jitter_max_seconds: int = 0
    timezone: str = "Asia/Shanghai"
    notify_mode: str = "log"
    user_agent: str = "daily-checkin-builder/1.0 (+authorized-automation)"


def _number(
    env: Mapping[str, str],
    key: str,
    default: str,
    kind: type,
    *,
    minimum: float,
    maximum: float,
) -> int | float:
    raw = env.get(key, default)
    try:
        value = kind(raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key} must be a valid {kind.__name__}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{key} must be between {minimum:g} and {maximum:g}")
    return value


def _validated_credential(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"account requires non-empty {field_name}")
    if any(not 32 <= ord(character) <= 126 for character in value):
        raise ConfigError(f"account {field_name} must contain only printable ASCII without control characters")
    credential = value.strip()
    if len(credential) > 16_384:
        raise ConfigError(f"account {field_name} is too long")
    return credential


def _secret_for(item: Mapping[str, object], auth_type: str) -> str:
    names = {"bearer": "token", "cookie": "cookie", "api_key": "api_key"}
    field_name = names[auth_type]
    value = item.get(field_name, item.get("secret"))
    return _validated_credential(value, field_name)


def _account(item: object, index: int) -> AccountConfig:
    if not isinstance(item, dict):
        raise ConfigError(f"CHECKIN_ACCOUNTS item {index} must be an object")
    allowed = {"name", "auth_type", "token", "cookie", "api_key", "secret", "cookie_name", "api_key_header", "sensitive_fields"}
    if set(item) - allowed:
        raise ConfigError(f"CHECKIN_ACCOUNTS item {index} contains unsupported fields")
    name = item.get("name")
    auth_type = item.get("auth_type")
    if not isinstance(name, str) or not ACCOUNT_NAME_RE.fullmatch(name) or PHONE_ALIAS_RE.fullmatch(name):
        raise ConfigError(f"CHECKIN_ACCOUNTS item {index} name must be a non-sensitive 1-64 character alias")
    if auth_type not in {"bearer", "cookie", "api_key"}:
        raise ConfigError(f"account {name!r} auth_type must be bearer, cookie, or api_key")
    sensitive = item.get("sensitive_fields", [])
    if (
        not isinstance(sensitive, list)
        or len(sensitive) > 32
        or not all(isinstance(value, str) and SENSITIVE_FIELD_RE.fullmatch(value) for value in sensitive)
    ):
        raise ConfigError(f"account {name!r} sensitive_fields must contain at most 32 safe field names")
    credential = _secret_for(item, auth_type)
    cookie_name = item.get("cookie_name", "session")
    api_key_header = item.get("api_key_header", "X-API-Key")
    if not isinstance(cookie_name, str) or not HEADER_NAME_RE.fullmatch(cookie_name):
        raise ConfigError(f"account {name!r} cookie_name must be a valid token")
    if not isinstance(api_key_header, str) or not HEADER_NAME_RE.fullmatch(api_key_header):
        raise ConfigError(f"account {name!r} api_key_header must be a valid HTTP header name")
    return AccountConfig(
        name,
        auth_type,
        credential,
        cookie_name=cookie_name,
        api_key_header=api_key_header,
        sensitive_fields=tuple(sensitive),
    )


def _accounts(env: Mapping[str, str]) -> tuple[AccountConfig, ...]:
    raw = env.get("CHECKIN_ACCOUNTS", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"CHECKIN_ACCOUNTS must be valid JSON: {exc.msg}") from exc
        if not isinstance(parsed, list) or not parsed or len(parsed) > MAX_ACCOUNTS:
            raise ConfigError(f"CHECKIN_ACCOUNTS must be a JSON array with 1-{MAX_ACCOUNTS} items")
        accounts = tuple(_account(item, index) for index, item in enumerate(parsed))
    else:
        auth_type = env.get("CHECKIN_AUTH_TYPE", "bearer").strip().lower()
        secret_names = {"bearer": "CHECKIN_TOKEN", "cookie": "CHECKIN_COOKIE", "api_key": "CHECKIN_API_KEY"}
        if auth_type not in secret_names:
            raise ConfigError("CHECKIN_AUTH_TYPE must be bearer, cookie, or api_key")
        key = secret_names[auth_type]
        raw_credential = env.get(key, "")
        if not raw_credential.strip():
            raise ConfigError(f"set {key}, or provide CHECKIN_ACCOUNTS")
        credential = _validated_credential(raw_credential, key)
        name = env.get("CHECKIN_ACCOUNT_NAME", "default")
        if not ACCOUNT_NAME_RE.fullmatch(name) or PHONE_ALIAS_RE.fullmatch(name):
            raise ConfigError("CHECKIN_ACCOUNT_NAME must be a non-sensitive 1-64 character alias")
        accounts = (AccountConfig(name, auth_type, credential),)
    names = [account.name.casefold() for account in accounts]
    if len(names) != len(set(names)):
        raise ConfigError("account names must be unique")
    return accounts


def _endpoint_path(value: str, name: str) -> str:
    if any(character.isspace() or ord(character) == 127 for character in value):
        raise ConfigError(f"{name} must not contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a valid same-origin path") from exc
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise ConfigError(f"{name} must be a same-origin path beginning with one /")
    sensitive_query_names = {
        "authorization", "cookie", "token", "access_token", "refresh_token",
        "auth_token", "api_key", "client_secret", "session_id", "csrf",
        "password", "passwd", "secret", "credential",
    }
    normalized_query = parsed.query.replace(";", "&")
    if any(key.casefold().replace("-", "_") in sensitive_query_names for key, _ in parse_qsl(normalized_query, keep_blank_values=True)):
        raise ConfigError(f"{name} must not contain credentials in its query string")
    return value


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    base_url = env.get("CHECKIN_BASE_URL", "").strip().rstrip("/")
    if any(character.isspace() or ord(character) == 127 for character in base_url):
        raise ConfigError("CHECKIN_BASE_URL must not contain whitespace or control characters")
    try:
        parsed = urlsplit(base_url)
        parsed.port
        hostname = parsed.hostname
    except ValueError as exc:
        raise ConfigError("CHECKIN_BASE_URL must be a valid HTTPS origin") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError("CHECKIN_BASE_URL must be an HTTPS origin without credentials, path, query, or fragment")
    base_url = f"https://{parsed.netloc}"
    status_path_value = env.get("CHECKIN_STATUS_PATH", "").strip()
    checkin_path_value = env.get("CHECKIN_ACTION_PATH", "").strip()
    if not status_path_value:
        raise ConfigError("set CHECKIN_STATUS_PATH from verified site-analysis evidence")
    if not checkin_path_value:
        raise ConfigError("set CHECKIN_ACTION_PATH from verified site-analysis evidence")
    status_path = _endpoint_path(status_path_value, "CHECKIN_STATUS_PATH")
    checkin_path = _endpoint_path(checkin_path_value, "CHECKIN_ACTION_PATH")
    connect_timeout = float(_number(env, "CHECKIN_CONNECT_TIMEOUT", "5", float, minimum=0.1, maximum=120))
    read_timeout = float(_number(env, "CHECKIN_READ_TIMEOUT", "15", float, minimum=0.1, maximum=120))
    timezone = env.get("CHECKIN_TIMEZONE", "Asia/Shanghai").strip()
    segments = timezone.split("/")
    if not TIMEZONE_RE.fullmatch(timezone) or any(segment in {".", ".."} for segment in segments):
        raise ConfigError("CHECKIN_TIMEZONE must name an installed IANA timezone such as Asia/Shanghai")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError("CHECKIN_TIMEZONE must name an installed IANA timezone such as Asia/Shanghai") from exc
    notify_mode = env.get("CHECKIN_NOTIFY_MODE", "log").strip().lower()
    if notify_mode not in {"log", "off"}:
        raise ConfigError("CHECKIN_NOTIFY_MODE must be log or off")
    return Settings(
        base_url=base_url,
        status_path=status_path,
        checkin_path=checkin_path,
        accounts=_accounts(env),
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        max_retries=int(_number(env, "CHECKIN_MAX_RETRIES", "2", int, minimum=0, maximum=5)),
        jitter_max_seconds=int(_number(env, "CHECKIN_JITTER_MAX_SECONDS", "0", int, minimum=0, maximum=900)),
        timezone=timezone,
        notify_mode=notify_mode,
    )
