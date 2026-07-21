# Site analysis record

Keep this file free of real cookies, tokens, account identifiers, and personal data. Replace samples with placeholders before committing.

## Scope and evidence

- Site and entry page: `https://checkin.example.invalid/` (reserved fictional origin)
- Check-in page: `https://checkin.example.invalid/account/checkin`
- Authorization scope: the operator's direct request declares the account and normal check-in scope; clarify only conflicts or expansions before a live request
- Evidence source: sanitized API documentation, HAR, cURL, Network capture, or existing code supplied by the authorized user
- Deployment targets: local Python, GitHub Actions, and QingLong

## Baseline contract (not site evidence)

The values below are reserved-domain scaffolding. A generated project must replace them only with facts established by authorized, sanitized evidence; delete unsupported authentication modes, fields, and business codes instead of guessing. Runtime configuration deliberately has no default endpoint paths, so an unfinished analysis fails before any request is sent.

1. The baseline can authenticate through one configured bearer token, cookie, or API key; retain only the evidenced mode.
2. `GET /api/checkin/status` returns business code `0`, a Boolean `data.checked_in`, and a CSRF token when not checked in.
3. `POST /api/checkin` sends JSON plus `X-CSRF-Token`.
4. The client accepts success only when `code` and `data.checked_in` confirm it. It treats an already-checked state as successful.
5. An ambiguous POST is followed by a status query; the POST is not automatically repeated.

## Request contract

- Status method/path: `GET /api/checkin/status`
- Check-in method/path: `POST /api/checkin`
- Query/form/multipart: none in this baseline
- JSON: `{"csrf_token":"sanitized-placeholder"}`
- Required headers: `Accept`, explicit `User-Agent`, one configured authentication header, `Content-Type` and `X-CSRF-Token` for POST
- Cookie/token use: authentication only; never persist or log it
- Cookie acquisition: first accept normal `Set-Cookie` updates in the per-account in-memory jar; otherwise require evidence for a documented refresh flow or an operator-provided, minimum first-party request Cookie stored as a protected secret
- CSRF acquisition: status response `data.csrf_token`
- Token refresh: intentionally not inferred; refresh credentials through the site's documented normal login flow
- Redirect behavior: not assumed; unexpected redirects are treated as site changes

## State evidence

- Success: HTTP 200, business `code: 0`, and `data.checked_in: true`
- Already done: status query reports `checked_in: true` or action returns `already_checked`
- Authentication expired: an evidenced HTTP 401 or documented authentication business code; never treat every 403 as authentication failure
- Temporary failure: timeout, 429, or retry-exhausted 5xx
- Site changed: malformed JSON, unexpected status, or missing fields
- Unsupported challenge: CAPTCHA, WebAuthn, device verification, or similar challenge; stop for manual handling

## Open assumptions to verify before live use

- Confirm paths, field names, authentication header, CSRF location, and exact business codes from sanitized evidence.
- Confirm whether any static, non-secret query parameters are required. Credentials must never be embedded in the base URL or endpoint path.
- Replace the baseline User-Agent with an honest automation identifier unless evidence proves that a specific documented value is required.
- Confirm whether the POST is idempotent. The baseline conservatively does not retry it.
- Confirm whether a balance or points delta is a useful secondary verification signal.
- Confirm that ordinary HTTPS requests are sufficient. Do not add browser automation merely for convenience and never bypass security controls.
