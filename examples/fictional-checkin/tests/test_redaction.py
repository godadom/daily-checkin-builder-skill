from __future__ import annotations

import logging
import unittest

from helpers import account
from checkin.logging_utils import RedactingFormatter, redact, safe_json


class RedactionTests(unittest.TestCase):
    def test_log_secret_redaction_covers_headers_nested_values_and_custom_fields(self):
        value = {
            "Authorization": "Bearer fixture-auth",
            "nested": {"password": "fixture-password", "member_id": "private-member"},
            "message": "token=fixture-token cookie=session-value",
        }
        rendered = safe_json(value, secret_values=["private-member"], sensitive_fields=["member_id"])
        for secret in ("fixture-auth", "fixture-password", "fixture-token", "session-value", "private-member"):
            self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_exception_text_is_redacted_by_formatter(self):
        record = logging.LogRecord("test", logging.ERROR, __file__, 1, "request failed: api_key=fixture-key", (), None)
        rendered = RedactingFormatter("%(message)s").format(record)
        self.assertNotIn("fixture-key", rendered)

    def test_free_text_masks_all_cookies_overlapping_secrets_and_custom_fields(self):
        rendered = redact(
            "Cookie: sid=fixture-one; refresh=fixture-two\n"
            "token=fixture-prefix-long member_id=private-member",
            secret_values=["fixture-prefix", "fixture-prefix-long"],
            sensitive_fields=["member_id"],
        )
        for secret in ("fixture-one", "fixture-two", "fixture-prefix", "fixture-prefix-long", "private-member"):
            self.assertNotIn(secret, rendered)
        self.assertGreaterEqual(rendered.count("[REDACTED]"), 3)

    def test_url_form_multi_account_unicode_and_short_values_are_masked(self):
        raw = (
            'url=https://checkin.example.invalid/?token=fixture-short-token&ok=1 '
            'password=fixture-password {"accounts":[{"token":"fixture-multi-account"}]} '
            'member_id=fixture-user email=user@example.invalid'
        )
        rendered = redact(raw, sensitive_fields=["member_id", "email"])
        for secret in ("fixture-short-token", "fixture-multi-account", "fixture-user", "user@example.invalid"):
            self.assertNotIn(secret, rendered)

    def test_normalized_sensitive_key_variants_are_masked(self):
        rendered = safe_json({
            "client-secret": "fixture-client-secret",
            "set_cookie": "sid=fixture-cookie",
            "device-id": "fixture-device",
            "message": "refresh-token=fixture-refresh custom-field=fixture-custom",
        }, sensitive_fields=["custom_field"])
        for secret in ("fixture-client-secret", "fixture-cookie", "fixture-device", "fixture-refresh", "fixture-custom"):
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
