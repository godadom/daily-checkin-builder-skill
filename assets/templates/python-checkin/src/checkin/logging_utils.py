"""Centralized structured redaction for logs and exception messages."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from typing import Any, Iterable


DEFAULT_SENSITIVE_KEYS = {
    "authorization", "cookie", "set_cookie", "token", "access_token",
    "refresh_token", "auth_token", "password", "passwd", "api_key",
    "apikey", "client_secret", "session", "session_id", "secret", "csrf",
    "csrf_token", "device_id", "user_id", "email", "phone", "identifier",
}
HEADER_PATTERN = re.compile(
    r"(?im)([\"']?(?:authorization|cookie|set-cookie)[\"']?\s*[:=]\s*)[^\r\n]+"
)


def _normalized_key(value: object) -> str:
    return str(value).strip().casefold().replace("-", "_")


def _redact_named_values(text: str, keys: set[str]) -> str:
    """Mask sensitive assignments in free-form logs and stringified errors."""

    if not keys:
        return text
    alternatives = "|".join(
        re.escape(key).replace("_", "[-_]")
        for key in sorted(keys, key=len, reverse=True)
    )
    pattern = re.compile(
        rf"(?i)([\"']?(?:{alternatives})[\"']?\s*[:=]\s*)"
        r"(?:Bearer\s+)?(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\]\r\n]+)"
    )
    return pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)


def redact(value: Any, *, secret_values: Iterable[str] = (), sensitive_fields: Iterable[str] = ()) -> Any:
    keys = DEFAULT_SENSITIVE_KEYS | {
        _normalized_key(key) for key in sensitive_fields if key
    }
    secrets = tuple(sorted({secret for secret in secret_values if secret}, key=len, reverse=True))
    if isinstance(value, Mapping):
        return {str(key): "[REDACTED]" if _normalized_key(key) in keys else redact(item, secret_values=secrets, sensitive_fields=keys) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item, secret_values=secrets, sensitive_fields=keys) for item in value]
    if isinstance(value, str):
        # Header values can contain several cookie pairs separated by semicolons;
        # mask the complete line before applying field-level masking.
        result = HEADER_PATTERN.sub(lambda match: f"{match.group(1)}[REDACTED]", value)
        result = _redact_named_values(result, keys)
        for secret in secrets:
            result = result.replace(secret, "[REDACTED]")
        return result
    return value


class RedactingFormatter(logging.Formatter):
    def __init__(self, *args, secret_values=(), sensitive_fields=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.secret_values = tuple(secret_values)
        self.sensitive_fields = tuple(sensitive_fields)

    def format(self, record: logging.LogRecord) -> str:
        return str(redact(super().format(record), secret_values=self.secret_values, sensitive_fields=self.sensitive_fields))


def configure_logging(secret_values=(), sensitive_fields=()) -> logging.Logger:
    logger = logging.getLogger("checkin")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(message)s", secret_values=secret_values, sensitive_fields=sensitive_fields))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def safe_json(value: Any, *, secret_values=(), sensitive_fields=()) -> str:
    return json.dumps(redact(value, secret_values=secret_values, sensitive_fields=sensitive_fields), ensure_ascii=False, sort_keys=True)
