from __future__ import annotations

import unittest

from helpers import account
from checkin.auth import AccountAuthProvider
from checkin.client import HttpResponse


class AuthProviderTests(unittest.TestCase):
    def test_cookie_updates_are_isolated_and_applied_to_later_requests(self):
        cookie_account = account(secret="session=fixture-old")
        cookie_account = type(cookie_account)(
            cookie_account.name,
            "cookie",
            cookie_account.secret,
        )
        provider = AccountAuthProvider(cookie_account)
        response = HttpResponse(
            200,
            {"Set-Cookie": "session=fixture-new; Path=/; Secure"},
            b"{}",
            header_items=(("Set-Cookie", "session=fixture-new; Path=/; Secure"),),
        )
        provider.observe(response)
        self.assertEqual(provider.headers(), {"Cookie": "session=fixture-new"})

    def test_refresh_callback_is_bounded_to_one_attempt(self):
        calls = []

        def refresh(item):
            calls.append(item.name)
            return "fixture-refreshed"

        provider = AccountAuthProvider(account(secret="fixture-old"), refresh)
        self.assertTrue(provider.refresh())
        self.assertFalse(provider.refresh())
        self.assertEqual(provider.headers(), {"Authorization": "Bearer fixture-refreshed"})
        self.assertEqual(calls, ["alice"])


if __name__ == "__main__":
    unittest.main()
