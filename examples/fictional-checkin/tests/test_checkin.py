from __future__ import annotations

import unittest
from dataclasses import replace

from helpers import account, fixture, response, service, settings
from checkin.auth import AccountAuthProvider
from checkin.client import HttpResponse
from checkin.models import CheckinResult, CheckinStatus, RunSummary
from checkin.main import execute_accounts, main, run
from unittest.mock import patch


class CheckinStateTests(unittest.TestCase):
    def test_success_response_requires_business_confirmation(self):
        worker, _ = service(fixture("status-unchecked.json"), fixture("checkin-success.json"))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.SUCCESS)
        self.assertEqual(result.details["points_delta"], 5)

    def test_untrusted_business_summary_fields_never_reach_logs(self):
        for unsafe in ("fixture-private-data", {"identifier": "fixture-private-data"}, True):
            with self.subTest(value=unsafe):
                worker, _ = service(
                    fixture("status-unchecked.json"),
                    response({"code": 0, "data": {"checked_in": True, "points_delta": unsafe}}),
                )
                result = worker.check_in(account())
                self.assertEqual(result.status, CheckinStatus.SITE_CHANGED)
                self.assertNotIn("fixture-private-data", str(result.details))

    def test_already_checked_response_is_successful(self):
        worker, transport = service(fixture("status-checked.json"))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.ALREADY_DONE)
        self.assertEqual([call["method"] for call in transport.calls], ["GET"])

    def test_action_409_already_checked_is_successful(self):
        worker, transport = service(fixture("status-unchecked.json"), response({"code": "already_checked", "data": {"checked_in": True}}, 409))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.ALREADY_DONE)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST"])

    def test_expired_cookie_or_token(self):
        worker, _ = service(response({"code": "auth_expired"}, 401))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.AUTH_EXPIRED)

    def test_missing_csrf_is_site_change(self):
        worker, transport = service(response({"code": 0, "data": {"checked_in": False}}))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
        self.assertEqual(len(transport.calls), 1)

    def test_unsafe_csrf_header_value_is_site_change(self):
        for unsafe in ("fixture" + chr(13) + chr(10) + "Injected", "fixture-" + chr(0x1F642), "x" * 4097):
            with self.subTest(length=len(unsafe)):
                worker, transport = service(response({"code": 0, "data": {"checked_in": False, "csrf_token": unsafe}}))
                self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
                self.assertEqual(len(transport.calls), 1)

    def test_invalid_csrf_is_auth_expired(self):
        worker, _ = service(fixture("status-unchecked.json"), response({"code": "csrf_invalid"}, 403))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.AUTH_EXPIRED)

    def test_403_is_classified_from_evidence_instead_of_assumed_auth(self):
        cases = (
            ({"code": "auth_expired"}, CheckinStatus.AUTH_EXPIRED),
            ({"code": "permission_denied"}, CheckinStatus.ACCESS_DENIED),
            ({"code": "unknown"}, CheckinStatus.SITE_CHANGED),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                worker, _ = service(response(payload, 403))
                self.assertEqual(worker.check_in(account()).status, expected)

    def test_changed_response_structure(self):
        worker, _ = service(fixture("schema-changed.json"))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)

    def test_business_code_requires_an_exact_integer_zero(self):
        for invalid_code in (False, 0.0):
            with self.subTest(stage="status", code=invalid_code):
                worker, transport = service(response({"code": invalid_code, "data": {"checked_in": False, "csrf_token": "fixture-csrf"}}))
                self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
                self.assertEqual(len(transport.calls), 1)
            with self.subTest(stage="action", code=invalid_code):
                worker, transport = service(
                    fixture("status-unchecked.json"),
                    response({"code": invalid_code, "data": {"checked_in": True}}),
                )
                self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
                self.assertEqual(len(transport.calls), 2)

    def test_html_login_page_and_cross_origin_redirect_are_not_followed(self):
        worker, _ = service(HttpResponse(200, {"Content-Type": "text/html"}, b"<html>login</html>"))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
        worker, transport = service(HttpResponse(302, {"Location": "https://other.example.invalid/login"}, b""))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
        self.assertEqual(len(transport.calls), 1)
        self.assertTrue(transport.calls[0]["url"].startswith("https://rewards.example.invalid/"))

    def test_security_challenge_is_not_bypassed(self):
        worker, _ = service(response({"code": "captcha_required"}, 403))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE)

    def test_documented_refresh_replays_only_the_safe_status_query(self):
        item = account(secret="fixture-old")
        provider = AccountAuthProvider(item, lambda _: "fixture-refreshed")
        worker, transport = service(
            response({"code": "auth_expired"}, 401),
            fixture("status-checked.json"),
            accounts=[item],
            auth_provider_factory=lambda _: provider,
        )
        self.assertEqual(worker.check_in(item).status, CheckinStatus.ALREADY_DONE)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "GET"])
        self.assertEqual(transport.calls[1]["headers"]["Authorization"], "Bearer fixture-refreshed")

    def test_refresh_after_rejected_post_confirms_without_repeating_post(self):
        item = account(secret="fixture-old")
        provider = AccountAuthProvider(item, lambda _: "fixture-refreshed")
        worker, transport = service(
            fixture("status-unchecked.json"),
            response({"code": "auth_expired"}, 401),
            fixture("status-checked.json"),
            accounts=[item],
            auth_provider_factory=lambda _: provider,
        )
        self.assertEqual(worker.check_in(item).status, CheckinStatus.SUCCESS)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST", "GET"])

    def test_partial_account_success_does_not_stop_later_accounts(self):
        accounts = [account("one"), account("two"), account("three")]
        def runner(item):
            if item.name == "two":
                raise RuntimeError("fixture failure")
            return CheckinResult(item.name, CheckinStatus.SUCCESS, "ok")
        summary = execute_accounts(accounts, runner)
        self.assertEqual([result.status for result in summary.results], [CheckinStatus.SUCCESS, CheckinStatus.INTERNAL_ERROR, CheckinStatus.SUCCESS])
        self.assertEqual(summary.exit_code, 70)

    def test_two_accounts_keep_authorization_values_isolated(self):
        worker, transport = service(fixture("status-checked.json"), fixture("status-checked.json"))
        results = [
            worker.check_in(account("one", "fixture-token-one")),
            worker.check_in(account("two", "fixture-token-two")),
        ]
        self.assertTrue(all(result.status is CheckinStatus.ALREADY_DONE for result in results))
        first = transport.calls[0]["headers"]["Authorization"]
        second = transport.calls[1]["headers"]["Authorization"]
        self.assertEqual((first, second), ("Bearer fixture-token-one", "Bearer fixture-token-two"))
        self.assertNotIn("fixture-token-one", second)

    def test_exit_code_mapping_and_failure_priority(self):
        success_summary = RunSummary.from_results([
            CheckinResult("one", CheckinStatus.SUCCESS, "fixture"),
            CheckinResult("two", CheckinStatus.ALREADY_DONE, "fixture"),
        ])
        self.assertEqual(success_summary.exit_code, 0)
        self.assertEqual(success_summary.status_counts["SUCCESS"], 1)
        self.assertEqual(success_summary.status_counts["ALREADY_DONE"], 1)
        expected = {
            CheckinStatus.CONFIG_ERROR: 2,
            CheckinStatus.AUTH_EXPIRED: 3,
            CheckinStatus.TEMPORARY_ERROR: 4,
            CheckinStatus.SITE_CHANGED: 5,
            CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE: 6,
            CheckinStatus.ACCESS_DENIED: 7,
            CheckinStatus.INTERNAL_ERROR: 70,
        }
        for status, code in expected.items():
            with self.subTest(status=status):
                self.assertEqual(RunSummary.from_results([CheckinResult("one", status, "fixture")]).exit_code, code)
        mixed = [CheckinResult(str(index), status, "fixture") for index, status in enumerate(expected)]
        self.assertEqual(RunSummary.from_results(mixed).exit_code, 7)
        self.assertEqual(RunSummary.from_results(mixed).status_counts["AUTH_EXPIRED"], 1)
        without_access = [result for result in mixed if result.status is not CheckinStatus.ACCESS_DENIED]
        self.assertEqual(RunSummary.from_results(without_access).exit_code, 6)
        temporary = CheckinResult("one", CheckinStatus.TEMPORARY_ERROR, "fixture", attempts=3)
        self.assertTrue(temporary.retry_recommended)
        self.assertTrue(temporary.retried)
        self.assertEqual(temporary.attempts, 3)

    def test_unclassified_top_level_exception_exits_70(self):
        with patch("checkin.main.load_settings", side_effect=RuntimeError("fixture internal failure")):
            self.assertEqual(main(), 70)

    def test_notification_failure_does_not_hide_checkin_result(self):
        success = CheckinResult("alice", CheckinStatus.SUCCESS, "ok")
        with patch("checkin.main.CheckinService.check_in", return_value=success), patch("checkin.main.notify", side_effect=RuntimeError("fixture")):
            self.assertEqual(run(settings()), 0)

    def test_log_notification_can_be_disabled(self):
        success = CheckinResult("alice", CheckinStatus.SUCCESS, "ok")
        with patch("checkin.main.CheckinService.check_in", return_value=success), patch("checkin.main.notify") as notifier:
            self.assertEqual(run(replace(settings(), notify_mode="off")), 0)
        notifier.assert_not_called()


if __name__ == "__main__":
    unittest.main()
