from __future__ import annotations

import unittest
import socket
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

from helpers import QueueTransport, account, deny_live_network, fixture, response, service
from checkin.client import (
    MAX_RESPONSE_BYTES,
    HttpResponse,
    ReliableHttpClient,
    ResponseTooLarge,
    read_bounded,
)
from checkin.models import CheckinStatus


class HttpReliabilityTests(unittest.TestCase):
    def test_global_socket_guard_blocks_accidental_live_network(self):
        self.assertIs(socket.create_connection, deny_live_network)
        with self.assertRaisesRegex(AssertionError, "must not open sockets"):
            deny_live_network()

    def test_response_body_cap_rejects_one_byte_over_limit_without_retry(self):
        class OversizedResponse:
            def read(self, limit):
                self.limit = limit
                return b"x" * limit

        source = OversizedResponse()
        with self.assertRaises(ResponseTooLarge):
            read_bounded(source)
        self.assertEqual(source.limit, MAX_RESPONSE_BYTES + 1)
        worker, transport = service(ResponseTooLarge("fixture oversized response"))
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SITE_CHANGED)
        self.assertEqual(len(transport.calls), 1)

    def test_network_timeout_becomes_temporary_error(self):
        worker, transport = service(TimeoutError(), TimeoutError(), TimeoutError())
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual(len(transport.calls), 3)

    def test_429_respects_bounded_get_retries(self):
        limited = response({"code": "rate_limited"}, 429, {"Retry-After": "0"})
        worker, transport = service(limited, limited, limited)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual(len(transport.calls), 3)

    def test_5xx_is_retried_only_within_bound(self):
        unavailable = response({"code": "unavailable"}, 503)
        worker, transport = service(unavailable, unavailable, unavailable)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual(len(transport.calls), 3)

    def test_html_security_challenge_stops_before_retry(self):
        challenge = HttpResponse(
            503,
            {"Content-Type": "text/html", "CF-Mitigated": "challenge"},
            b"<html><title>Just a moment</title><div>cf-chl</div></html>",
        )
        worker, transport = service(challenge)
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE)
        self.assertEqual(len(transport.calls), 1)

    def test_sms_or_mfa_challenge_json_stops_before_retry(self):
        for code in ("device_verification_required", "sms_required", "otp_required", "mfa_required", "security_verification_required"):
            with self.subTest(code=code):
                worker, transport = service(response({"code": code}, 503))
                self.assertEqual(worker.check_in(account()).status, CheckinStatus.UNSUPPORTED_SECURITY_CHALLENGE)
                self.assertEqual(len(transport.calls), 1)

    def test_markerless_html_5xx_is_site_change_without_retry(self):
        changed = HttpResponse(
            503,
            {"Content-Type": "text/html"},
            b"<html><title>Maintenance response</title></html>",
        )
        worker, transport = service(changed)
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.SITE_CHANGED)
        self.assertEqual(len(transport.calls), 1)

    def test_ambiguous_post_is_never_repeated(self):
        worker, transport = service(fixture("status-unchecked.json"), TimeoutError(), fixture("status-checked.json"))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.SUCCESS)
        self.assertEqual([call["method"] for call in transport.calls].count("POST"), 1)

    def test_failed_post_queries_status_before_any_future_attempt(self):
        worker, transport = service(fixture("status-unchecked.json"), response({"code": "busy"}, 503), fixture("status-unchecked.json"))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST", "GET"])

    def test_every_5xx_post_is_treated_as_ambiguous_without_repeat(self):
        worker, transport = service(fixture("status-unchecked.json"), response({"code": "unknown"}, 501), fixture("status-unchecked.json"))
        result = worker.check_in(account())
        self.assertEqual(result.status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST", "GET"])

    def test_retry_after_seconds_and_http_date_are_honored(self):
        delays = []
        transport = QueueTransport(response({"code": "busy"}, 429, {"Retry-After": "7"}), response({"code": 0}))
        client = ReliableHttpClient(transport, max_retries=1, sleeper=delays.append)
        result = client.request("GET", "https://checkin.example.invalid/status", {})
        self.assertEqual((delays, result.attempts), ([7.0], 2))
        future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=20))
        parsed = client._retry_after({"Retry-After": future}, 1)
        self.assertGreater(parsed, 0)
        self.assertLessEqual(parsed, 60)
        self.assertIsNone(client._retry_after({"Retry-After": "120"}, 1))

    def test_retry_after_over_safe_cap_stops_without_an_early_request(self):
        delays = []
        limited = response({"code": "rate_limited"}, 429, {"Retry-After": "120"})
        transport = QueueTransport(limited)
        client = ReliableHttpClient(transport, max_retries=2, sleeper=delays.append)
        result = client.request("GET", "https://checkin.example.invalid/status", {})
        self.assertEqual((result.status, result.attempts), (429, 1))
        self.assertEqual((len(transport.calls), delays), (1, []))

    def test_post_429_waits_before_one_confirmation_or_stops_at_cap(self):
        delays = []
        transport = QueueTransport(
            fixture("status-unchecked.json"),
            response({"code": "rate_limited"}, 429, {"Retry-After": "7"}),
            fixture("status-checked.json"),
        )
        worker, _ = service()
        worker.client = ReliableHttpClient(transport, max_retries=2, sleeper=delays.append)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SUCCESS)
        self.assertEqual(([call["method"] for call in transport.calls], delays), (["GET", "POST", "GET"], [7.0]))

        transport = QueueTransport(
            fixture("status-unchecked.json"),
            response({"code": "rate_limited"}, 429, {"Retry-After": "120"}),
        )
        worker, _ = service()
        worker.client = ReliableHttpClient(transport, max_retries=2, sleeper=delays.append)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST"])
        self.assertEqual(delays, [7.0])

    def test_post_5xx_retry_after_is_respected_before_confirmation(self):
        delays = []
        transport = QueueTransport(
            fixture("status-unchecked.json"),
            response({"code": "busy"}, 503, {"Retry-After": "5"}),
            fixture("status-checked.json"),
        )
        worker, _ = service()
        worker.client = ReliableHttpClient(transport, max_retries=2, sleeper=delays.append)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.SUCCESS)
        self.assertEqual(delays, [5.0])
        transport = QueueTransport(
            fixture("status-unchecked.json"),
            response({"code": "busy"}, 503, {"Retry-After": "120"}),
        )
        worker, _ = service()
        worker.client = ReliableHttpClient(transport, max_retries=2, sleeper=delays.append)
        self.assertEqual(worker.check_in(account()).status, CheckinStatus.TEMPORARY_ERROR)
        self.assertEqual([call["method"] for call in transport.calls], ["GET", "POST"])

    def test_exponential_backoff_and_request_contract(self):
        delays = []
        transport = QueueTransport(TimeoutError(), TimeoutError(), fixture("status-checked.json"))
        client = ReliableHttpClient(transport, connect_timeout=4, read_timeout=9, max_retries=2, sleeper=delays.append)
        worker, _ = service(fixture("status-checked.json"))
        worker.client = client
        result = worker.check_in(account(secret="fixture-token"))
        self.assertEqual(result.status, CheckinStatus.ALREADY_DONE)
        self.assertEqual(delays, [1, 2])
        call = transport.calls[-1]
        self.assertEqual(call["timeouts"], (4, 9))
        self.assertEqual(call["headers"]["User-Agent"], "daily-checkin-builder/1.0 (+authorized-automation)")
        self.assertEqual(call["headers"]["Authorization"], "Bearer fixture-token")


if __name__ == "__main__":
    unittest.main()
