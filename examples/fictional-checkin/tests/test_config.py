from __future__ import annotations

import json
import unittest

from helpers import account
from checkin.auth import authentication_headers
from checkin.config import ConfigError, load_settings


class ConfigTests(unittest.TestCase):
    def test_configuration_read_and_field_validation(self):
        env = {"CHECKIN_BASE_URL": "https://checkin.example.invalid", "CHECKIN_TOKEN": "placeholder"}
        settings = load_settings(env)
        self.assertEqual(settings.base_url, "https://checkin.example.invalid")
        with self.assertRaisesRegex(ConfigError, "HTTPS origin"):
            load_settings({**env, "CHECKIN_BASE_URL": "http://unsafe.invalid"})
        with self.assertRaisesRegex(ConfigError, "installed IANA timezone"):
            load_settings({**env, "CHECKIN_TIMEZONE": "Shanghai"})
        with self.assertRaisesRegex(ConfigError, "installed IANA timezone"):
            load_settings({**env, "CHECKIN_TIMEZONE": "Etc/DefinitelyMissing"})
        self.assertEqual(load_settings({**env, "CHECKIN_TIMEZONE": "UTC"}).timezone, "UTC")
        with self.assertRaisesRegex(ConfigError, "CHECKIN_NOTIFY_MODE"):
            load_settings({**env, "CHECKIN_NOTIFY_MODE": "webhook"})
        self.assertEqual(load_settings({**env, "CHECKIN_NOTIFY_MODE": "off"}).notify_mode, "off")

    def test_origin_and_endpoint_paths_cannot_change_request_authority(self):
        env = {"CHECKIN_BASE_URL": "https://checkin.example.invalid", "CHECKIN_TOKEN": "placeholder"}
        for unsafe_origin in (
            "https://checkin.example.invalid/api",
            "https://checkin.example.invalid?token=fixture-secret",
            "https://checkin.example.invalid/#fragment",
            "https://user:fixture-secret@checkin.example.invalid",
        ):
            with self.subTest(origin=unsafe_origin), self.assertRaisesRegex(ConfigError, "HTTPS origin"):
                load_settings({**env, "CHECKIN_BASE_URL": unsafe_origin})
        for key, value in (
            ("CHECKIN_STATUS_PATH", "//other.example.invalid/status"),
            ("CHECKIN_ACTION_PATH", "https://other.example.invalid/checkin"),
            ("CHECKIN_ACTION_PATH", "/api/checkin#fragment"),
        ):
            with self.subTest(key=key, value=value), self.assertRaisesRegex(ConfigError, "same-origin path"):
                load_settings({**env, key: value})
        with self.assertRaisesRegex(ConfigError, "must not contain credentials"):
            load_settings({**env, "CHECKIN_STATUS_PATH": "/api/status?access%5Ftoken=fixture-secret"})
        with self.assertRaisesRegex(ConfigError, "must not contain credentials"):
            load_settings({**env, "CHECKIN_STATUS_PATH": "/api/status?locale=en;password=fixture-secret"})
        self.assertEqual(
            load_settings({**env, "CHECKIN_STATUS_PATH": "/api/status?locale=en"}).status_path,
            "/api/status?locale=en",
        )

    def test_single_account_parsing(self):
        settings = load_settings({
            "CHECKIN_BASE_URL": "https://checkin.example.invalid",
            "CHECKIN_AUTH_TYPE": "cookie",
            "CHECKIN_COOKIE": "session=placeholder",
            "CHECKIN_ACCOUNT_NAME": "primary",
        })
        self.assertEqual((settings.accounts[0].name, settings.accounts[0].auth_type), ("primary", "cookie"))

    def test_multi_account_parsing_and_friendly_errors(self):
        raw = json.dumps([
            {"name": "one", "auth_type": "bearer", "token": "placeholder-one"},
            {"name": "two", "auth_type": "api_key", "api_key": "placeholder-two"},
        ])
        settings = load_settings({"CHECKIN_BASE_URL": "https://checkin.example.invalid", "CHECKIN_ACCOUNTS": raw})
        self.assertEqual([item.name for item in settings.accounts], ["one", "two"])
        duplicate = json.dumps([
            {"name": "Same", "auth_type": "bearer", "token": "placeholder-one"},
            {"name": "same", "auth_type": "bearer", "token": "placeholder-two"},
        ])
        with self.assertRaisesRegex(ConfigError, "unique"):
            load_settings({"CHECKIN_BASE_URL": "https://checkin.example.invalid", "CHECKIN_ACCOUNTS": duplicate})
        with self.assertRaisesRegex(ConfigError, "valid JSON"):
            load_settings({"CHECKIN_BASE_URL": "https://checkin.example.invalid", "CHECKIN_ACCOUNTS": "["})

    def test_resource_bounds_and_safe_identifiers(self):
        env = {"CHECKIN_BASE_URL": "https://rewards.example.invalid", "CHECKIN_TOKEN": "placeholder"}
        for key, value in (
            ("CHECKIN_CONNECT_TIMEOUT", "121"),
            ("CHECKIN_READ_TIMEOUT", "0"),
            ("CHECKIN_MAX_RETRIES", "6"),
            ("CHECKIN_JITTER_MAX_SECONDS", "901"),
        ):
            with self.subTest(key=key), self.assertRaisesRegex(ConfigError, "must be between"):
                load_settings({**env, key: value})
        with self.assertRaisesRegex(ConfigError, "non-sensitive"):
            load_settings({**env, "CHECKIN_ACCOUNT_NAME": "user@example.invalid"})
        unsafe_alias = "138" + "0013" + "8000"
        with self.assertRaisesRegex(ConfigError, "non-sensitive"):
            load_settings({**env, "CHECKIN_ACCOUNT_NAME": unsafe_alias})
        unsafe_item = {
            "name": "safe-alias",
            "auth_type": "api_key",
            "api_key": "placeholder-key",
        }
        unsafe_item["api_key" + "_header"] = "fixture-invalid-header" + chr(13) + chr(10) + "Injected"
        unsafe_account = json.dumps([unsafe_item])
        with self.assertRaisesRegex(ConfigError, "valid HTTP header"):
            load_settings({"CHECKIN_BASE_URL": "https://rewards.example.invalid", "CHECKIN_ACCOUNTS": unsafe_account})
        for unsafe_url in ("https:" + "//[", "https://rewards.example.invalid:99999"):
            with self.subTest(url=unsafe_url), self.assertRaisesRegex(ConfigError, "valid HTTPS origin"):
                load_settings({**env, "CHECKIN_BASE_URL": unsafe_url})
        with self.assertRaisesRegex(ConfigError, "control characters"):
            load_settings({**env, "CHECKIN_STATUS_PATH": "/api/status\r\nInjected"})
        unsafe_secret = "placeholder" + chr(13) + chr(10) + "Injected"
        with self.assertRaisesRegex(ConfigError, "control characters"):
            load_settings({**env, "CHECKIN_TOKEN": unsafe_secret})
        with self.assertRaisesRegex(ConfigError, "installed IANA timezone"):
            load_settings({**env, "CHECKIN_TIMEZONE": "../Asia/Shanghai"})

    def test_authentication_header_is_built_without_logging(self):
        self.assertEqual(authentication_headers(account(secret="fixture-secret")), {"Authorization": "Bearer fixture-secret"})


if __name__ == "__main__":
    unittest.main()
