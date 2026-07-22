from __future__ import annotations

import unittest

from checkin.interactive_login import (
    InteractiveLoginRunner,
    LoginCredentials,
    LoginObservation,
    LoginState,
)


class FakeSession:
    def __init__(self, states, cookies=None, start_error=False):
        self.states = list(states)
        self.cookies = dict(cookies or {})
        self.start_error = start_error
        self.context_id = object()
        self.seen_context_ids = []
        self.received_credentials = None
        self.closed = False

    def start(self, credentials):
        if self.start_error:
            raise RuntimeError("browser unavailable")
        self.received_credentials = credentials

    def observe(self):
        self.seen_context_ids.append(id(self.context_id))
        if not self.states:
            return LoginObservation(LoginState.WAITING_FOR_CREDENTIALS)
        return LoginObservation(self.states.pop(0))

    def read_cookies(self, allowed_origins):
        self.seen_context_ids.append(id(self.context_id))
        return self.cookies

    def close(self):
        self.closed = True


class FakeStore:
    def __init__(self, fail=False):
        self.fail = fail
        self.saved = []

    def save_cookie(self, account_alias, cookie_header):
        if self.fail:
            raise RuntimeError("store failed")
        self.saved.append((account_alias, cookie_header))


class FakeTime:
    def __init__(self):
        self.value = 0.0

    def now(self):
        return self.value

    def wait(self, seconds):
        self.value += seconds


class InteractiveLoginTests(unittest.TestCase):
    def runner(self, session, store, presenter=None, fake_time=None):
        fake_time = fake_time or FakeTime()
        return InteractiveLoginRunner(
            session,
            store,
            allowed_origins=("https://example.invalid",),
            required_cookie_names=("session", "csrf"),
            timeout_seconds=3,
            poll_seconds=1,
            presenter=presenter,
            clock=fake_time.now,
            wait=fake_time.wait,
        )

    def test_password_login_keeps_context_for_human_challenge_and_saves_whitelist(self):
        opaque_value = "fixture-password-value"
        session = FakeSession(
            [
                LoginState.WAITING_FOR_CREDENTIALS,
                LoginState.WAITING_FOR_CHALLENGE,
                LoginState.SUCCESS,
            ],
            {
                "session": "fixture-session-value",
                "csrf": "fixture-csrf-value",
                "tracking": "fixture-tracking-value",
            },
        )
        store = FakeStore()
        presented = []
        credentials = LoginCredentials("fixture-user", opaque_value)

        result = self.runner(session, store, lambda state, message: presented.append((state, message))).run(
            "account-a", credentials
        )

        self.assertEqual(result.state, LoginState.SUCCESS)
        self.assertTrue(result.stored)
        self.assertEqual(
            store.saved,
            [("account-a", "session=fixture-session-value; csrf=fixture-csrf-value")],
        )
        self.assertEqual(len(set(session.seen_context_ids)), 1)
        self.assertNotIn(opaque_value, repr(credentials))
        self.assertNotIn(opaque_value, repr(result))
        self.assertNotIn(opaque_value, repr(presented))
        self.assertTrue(session.closed)

    def test_otp_and_challenge_are_waiting_states_for_manual_page_input(self):
        session = FakeSession(
            [LoginState.WAITING_FOR_OTP, LoginState.WAITING_FOR_CHALLENGE, LoginState.REJECTED]
        )
        presented = []

        result = self.runner(
            session,
            FakeStore(),
            lambda state, message: presented.append(state),
        ).run("account-b")

        self.assertEqual(result.state, LoginState.REJECTED)
        self.assertEqual(
            presented,
            [LoginState.WAITING_FOR_OTP, LoginState.WAITING_FOR_CHALLENGE],
        )
        self.assertTrue(session.closed)

    def test_timeout_is_bounded_and_closes_session(self):
        fake_time = FakeTime()
        session = FakeSession([])
        result = self.runner(session, FakeStore(), fake_time=fake_time).run("account-c")
        self.assertEqual(result.state, LoginState.TIMEOUT)
        self.assertEqual(fake_time.value, 3)
        self.assertTrue(session.closed)

    def test_missing_required_cookie_is_site_changed_and_not_stored(self):
        session = FakeSession(
            [LoginState.SUCCESS],
            {"session": "fixture-session-value"},
        )
        store = FakeStore()
        result = self.runner(session, store).run("account-d")
        self.assertEqual(result.state, LoginState.SITE_CHANGED)
        self.assertEqual(store.saved, [])

    def test_storage_failure_does_not_expose_cookie(self):
        session = FakeSession(
            [LoginState.SUCCESS],
            {"session": "fixture-session-value", "csrf": "fixture-csrf-value"},
        )
        result = self.runner(session, FakeStore(fail=True)).run("account-e")
        self.assertEqual(result.state, LoginState.STORAGE_ERROR)
        self.assertNotIn("fixture-session-value", repr(result))
        self.assertNotIn("fixture-csrf-value", repr(result))

    def test_unavailable_visible_browser_is_distinct(self):
        session = FakeSession([], start_error=True)
        result = self.runner(session, FakeStore()).run("account-f")
        self.assertEqual(result.state, LoginState.LOGIN_UI_UNAVAILABLE)
        self.assertTrue(session.closed)

    def test_cookie_value_cannot_inject_another_cookie(self):
        names = ("session", "csrf")
        session = FakeSession(
            [LoginState.SUCCESS],
            dict(zip(names, (";".join(("fixture-value", "injected=fixture")), "fixture-csrf-value"))),
        )
        store = FakeStore()
        result = self.runner(session, store).run("account-g")
        self.assertEqual(result.state, LoginState.SITE_CHANGED)
        self.assertEqual(store.saved, [])

    def test_allowed_origins_must_be_https_origins(self):
        with self.assertRaises(ValueError):
            InteractiveLoginRunner(
                FakeSession([]),
                FakeStore(),
                allowed_origins=("http://example.invalid/login",),
                required_cookie_names=("session",),
            )


if __name__ == "__main__":
    unittest.main()
