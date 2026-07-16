# Sanitized fictional evidence

Every hostname, account label, token, cookie, CSRF value, identifier, and response below is fabricated. `example.invalid` is reserved for examples. This evidence is safe to keep in the repository and must not be replaced with raw production captures.

## Status request

```text
curl 'https://rewards.example.invalid/v1/daily/status' \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer <REDACTED_AUTHORIZED_TOKEN>' \
  -H 'User-Agent: ExampleRewards-Web/1.0'
```

Sanitized successful response before check-in:

```json
{"code":0,"data":{"checked_in":false,"csrf_token":"<REDACTED_CSRF>"}}
```

## Check-in request

```text
curl 'https://rewards.example.invalid/v1/daily/claim' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Authorization: Bearer <REDACTED_AUTHORIZED_TOKEN>' \
  -H 'Content-Type: application/json' \
  -H 'X-CSRF-Token: <REDACTED_CSRF>' \
  --data-raw '{"csrf_token":"<REDACTED_CSRF>"}'
```

Sanitized business-success response:

```json
{"code":0,"data":{"checked_in":true,"points_delta":5}}
```

Sanitized already-done response:

```json
{"code":"already_checked","data":{"checked_in":true}}
```

Sanitized HTTP 401 authentication failure:

```json
{"code":"auth_expired"}
```

Sanitized HTTP 403 CSRF failure:

```json
{"code":"csrf_invalid"}
```

Sanitized HTTP 403 permission failure:

```json
{"code":"permission_denied"}
```

## Derived implementation decisions

- Query status before action and accept `checked_in: true` as `ALREADY_DONE`.
- Read the CSRF token only from the status response; do not invent or persist it.
- Require both `code: 0` and `checked_in: true` for `SUCCESS`.
- Do not retry the POST. If its outcome is ambiguous, query status once and report either confirmed success or a temporary error.
- Treat a CAPTCHA, WebAuthn, WAF, device-verification, or similar response as an unsupported security challenge.
- Treat an unknown HTTP 403 or markerless HTML response as a site change until new sanitized evidence is available.
