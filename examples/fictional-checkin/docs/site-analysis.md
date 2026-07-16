# Example Rewards site analysis record

Keep this file free of real cookies, tokens, account identifiers, and personal data. Replace samples with placeholders before committing.

## Scope and evidence

- Site and entry page: `https://rewards.example.invalid/` (reserved fictional origin)
- Check-in page: `https://rewards.example.invalid/member/daily`
- Authorization confirmation: required before enabling any live request
- Evidence source: `docs/sanitized-evidence.md`, a fabricated and fully sanitized cURL/response transcript
- Deployment targets: local Python, GitHub Actions, and QingLong

## Observed flow

Runtime configuration deliberately has no default endpoint paths; it must use the two paths established by this fictional evidence or fail before any request is sent.

1. The fabricated transcript observes a bearer token. Cookie and API-key support are generic template capabilities, not observed facts for this example.
2. `GET /v1/daily/status` returns business code `0`, a Boolean `data.checked_in`, and a CSRF token when not checked in.
3. `POST /v1/daily/claim` sends JSON plus `X-CSRF-Token`.
4. The client accepts success only when `code` and `data.checked_in` confirm it. It treats an already-checked state as successful.
5. An ambiguous POST is followed by a status query; the POST is not automatically repeated.

## Request contract

- Status method/path: `GET /v1/daily/status`
- Check-in method/path: `POST /v1/daily/claim`
- Query/form/multipart: none in this baseline
- JSON: `{"csrf_token":"sanitized-placeholder"}`
- Required headers: `Accept`, explicit `User-Agent`, one configured authentication header, `Content-Type` and `X-CSRF-Token` for POST
- User-Agent decision: the transcript's browser label is evidence of the captured client only, not a server requirement; the implementation uses the honest `daily-checkin-builder/1.0 (+authorized-automation)` identifier
- Cookie/token use: authentication only; never persist or log it
- CSRF acquisition: status response `data.csrf_token`
- Token refresh: intentionally not inferred; refresh credentials through the site's documented normal login flow
- Redirect behavior: not assumed; unexpected redirects are treated as site changes

## State evidence

- Success: HTTP 200, business `code: 0`, and `data.checked_in: true`
- Already done: status query reports `checked_in: true` or action returns `already_checked`
- Authentication expired: evidenced HTTP 401 with `auth_expired`, or HTTP 403 with `csrf_invalid`
- Permission denied: evidenced HTTP 403 with `permission_denied`; stop as `UNSUPPORTED_SECURITY_CHALLENGE` rather than retrying or bypassing
- Unknown HTTP 403: `SITE_CHANGED` until new sanitized evidence explains it
- Temporary failure: timeout, 429, or retry-exhausted 5xx
- Site changed: malformed JSON, unexpected status, or missing fields
- Unsupported challenge: CAPTCHA, WebAuthn, device verification, or similar challenge; stop for manual handling

## Open assumptions and example boundary

- The paths, field names, bearer header, CSRF location, and business codes are consistent across the fabricated evidence and mock tests.
- Cookie and API-key authentication remain unverified capabilities and must not be enabled for this fictional contract without new evidence.
- Confirm whether the POST is idempotent. The baseline conservatively does not retry it.
- Confirm whether a balance or points delta is a useful secondary verification signal.
- Confirm that ordinary HTTPS requests are sufficient. Do not add browser automation merely for convenience and never bypass security controls.
- This example must not be repointed at a live site without a fresh authorized analysis. No claim is made that its fictional contract matches any real service.
