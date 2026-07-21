# Authorized daily check-in

This reusable Python 3 baseline automates a daily check-in only for an account and site the operator is authorized to automate. It supports local execution, GitHub Actions, and QingLong through the same `run.py` business entry point. It does not bypass CAPTCHA, WAF, WebAuthn, device verification, paywalls, permissions, or anti-bot challenges.

## How it works

For each account, the service queries today's state, obtains a CSRF token, sends one check-in request, and validates the business payload. `SUCCESS` and `ALREADY_DONE` are successful. `AUTH_EXPIRED` asks the operator to refresh credentials. `ACCESS_DENIED` means the authenticated account lacks permission. `TEMPORARY_ERROR` covers bounded transport failures. `SITE_CHANGED` indicates that the documented response contract no longer matches. `CONFIG_ERROR` is an environment problem. `UNSUPPORTED_SECURITY_CHALLENGE` stops rather than evading a security control. `INTERNAL_ERROR` records an unclassified, redacted implementation failure.

## Configuration

First replace the non-secret site facts in `src/checkin/site_config.py` using verified `docs/site-analysis.md` evidence. They are intentionally source-controlled and cannot be overridden through environment variables. Use environment variables only for secrets and runtime choices.

| Variable | Required | Meaning |
| --- | --- | --- |
| `CHECKIN_AUTH_TYPE` | single account | `bearer`, `cookie`, or `api_key` |
| `CHECKIN_TOKEN` / `CHECKIN_COOKIE` / `CHECKIN_API_KEY` | single account | Secret matching the auth type |
| `CHECKIN_ACCOUNT_NAME` | no | Non-secret log label |
| `CHECKIN_ACCOUNTS` | multiple accounts | JSON array described below; overrides single-account fields |
| `CHECKIN_CONNECT_TIMEOUT` | no | Connection timeout seconds; default 5 |
| `CHECKIN_READ_TIMEOUT` | no | Read timeout seconds; default 15 |
| `CHECKIN_MAX_RETRIES` | no | Safe-request retry count; default 2 |
| `CHECKIN_JITTER_MAX_SECONDS` | no | Small scheduling jitter; not a security-evasion feature |
| `CHECKIN_TIMEZONE` | no | IANA display/runtime timezone; default `Asia/Shanghai` |
| `CHECKIN_NOTIFY_MODE` | no | `log` (redacted stdout summary, default) or `off`; no external sender is bundled |

Multi-account example (store the whole value as one secret):

```json
[
  {"name":"account-a","auth_type":"bearer","token":"replace-with-authorized-token"},
  {"name":"account-b","auth_type":"cookie","cookie":"session=replace-with-authorized-cookie","sensitive_fields":["member_id"]}
]
```

Account failures are isolated and execution is serial by default. Exit codes are `0` for all-success/already-done, `2` for configuration, `3` for expired authentication, `4` for temporary errors, `5` for site changes, `6` for unsupported security challenges, `7` for access denied, and `70` for unclassified internal errors. When several failures occur, priority is access denied, security challenge, configuration, site change, authentication, temporary error, then internal error. The logged summary retains the count for every status.

## Local use

Use Python 3.11 or newer. Set secrets in the shell or a local, gitignored `.env` loader of your choice; never pass secrets as command-line arguments.

```text
python -m pip install -r requirements.txt
python tests/run_offline.py
python run.py
```

The HTTP and business implementation uses the standard library. Responses are capped at 1 MiB before parsing. Authentication state is isolated per account: cookie responses update only that account's small cookie jar, and a site-specific integration may inject one documented refresh callback. The default provider never invents a login or refresh endpoint. Tests inject mock HTTP responses and never contact a real site. The fixed origin and endpoint paths are mandatory in `site_config.py`, so incomplete configuration cannot fall back to invented routes. A live run occurs only when valid secret configuration is supplied; there is no automatic `LIVE_TEST` path in CI.

## Deployment

See `DEPLOY_GITHUB.md` for Secrets, variables, schedule, logs, and disabling the workflow. See `DEPLOY_QINGLONG.md` for the Python command, cron, environment setup, manual execution, and troubleshooting.

## Troubleshooting and safety

- `AUTH_EXPIRED`: perform the site's normal login or documented token refresh, then replace the secret. Do not scrape browser databases.
- `ACCESS_DENIED`: stop the task and verify account entitlement or site policy; do not retry or bypass permissions.
- `SITE_CHANGED`: compare a newly sanitized Network capture with `docs/site-analysis.md`, update the response parser, and extend mock fixtures before deploying.
- `TEMPORARY_ERROR`: check service health, rate-limit headers, and timeout settings. Do not increase concurrency to defeat limits.
- `UNSUPPORTED_SECURITY_CHALLENGE`: complete the site's intended manual flow; do not automate around it.
- Never log full request headers, commit populated secret files, or put credentials in a URL or command line.
