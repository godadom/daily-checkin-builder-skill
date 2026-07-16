"""Translate validated account credentials into request headers."""

from __future__ import annotations

from .models import AccountConfig


def authentication_headers(account: AccountConfig) -> dict[str, str]:
    if account.auth_type == "bearer":
        return {"Authorization": f"Bearer {account.secret}"}
    if account.auth_type == "cookie":
        cookie_header = account.secret if "=" in account.secret else f"{account.cookie_name}={account.secret}"
        return {"Cookie": cookie_header}
    if account.auth_type == "api_key":
        return {account.api_key_header: account.secret}
    raise ValueError("unsupported validated auth type")
