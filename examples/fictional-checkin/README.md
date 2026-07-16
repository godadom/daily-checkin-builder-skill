# Fictional Example Rewards daily check-in

This complete example shows the project generated from the deliberately fictional, sanitized evidence in `docs/sanitized-evidence.md`. The origin uses the reserved `.invalid` namespace and cannot identify a production site. It supports local execution, GitHub Actions, and QingLong through the same `run.py` business entry point. For a real deployment, use only an account and site the operator is authorized to automate. The project does not bypass CAPTCHA, WAF, WebAuthn, device verification, paywalls, permissions, or anti-bot challenges.

## How it works

For each account, the service queries today's state, obtains a CSRF token, sends one check-in request, and validates the business payload. `SUCCESS` and `ALREADY_DONE` are successful. `AUTH_EXPIRED` asks the operator to refresh credentials. `TEMPORARY_ERROR` covers bounded transport failures. `SITE_CHANGED` indicates that the documented response contract no longer matches. `CONFIG_ERROR` is an environment problem. `UNSUPPORTED_SECURITY_CHALLENGE` stops rather than evading a security control. `INTERNAL_ERROR` records an unclassified, redacted implementation failure.

The fictional evidence maps `GET /v1/daily/status` to the preflight/status query and `POST /v1/daily/claim` to the action. `.env.example` records those verified example paths; source-code defaults remain generic and are always overridden in deployment.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `CHECKIN_BASE_URL` | yes | Authorized HTTPS origin, without credentials |
| `CHECKIN_STATUS_PATH` | no | Status endpoint; default `/api/checkin/status` |
| `CHECKIN_ACTION_PATH` | no | Check-in endpoint; default `/api/checkin` |
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

Account failures are isolated and execution is serial by default. Exit codes are `0` for all-success/already-done, `2` for configuration, `3` for expired authentication, `4` for temporary errors, `5` for site changes, `6` for unsupported security challenges, and `70` for unclassified internal errors. When several failures occur, priority is security challenge, configuration, site change, authentication, temporary error, then internal error. The logged summary retains the count for every status.

## Local use

Use Python 3.11 or newer. Set secrets in the shell or a local, gitignored `.env` loader of your choice; never pass secrets as command-line arguments.

```text
python -m pip install -r requirements.txt
python tests/run_offline.py
python run.py
```

The HTTP and business implementation uses the standard library. Responses are capped at 1 MiB before parsing. The pinned `tzdata` package supplies a consistent IANA database on Windows and minimal containers, while `zoneinfo.ZoneInfo` validates the configured zone. Tests inject mock HTTP responses and never contact a real site. A live run occurs only when valid environment configuration is supplied; there is no automatic `LIVE_TEST` path in CI.

## Deployment

See `DEPLOY_GITHUB.md` for Secrets, variables, schedule, logs, and disabling the workflow. See `DEPLOY_QINGLONG.md` for the Python command, cron, environment setup, manual execution, and troubleshooting.

## Troubleshooting and safety

- `AUTH_EXPIRED`: perform the site's normal login or documented token refresh, then replace the secret. Do not scrape browser databases.
- `SITE_CHANGED`: compare a newly sanitized Network capture with `docs/site-analysis.md`, update the response parser, and extend mock fixtures before deploying.
- `TEMPORARY_ERROR`: check service health, rate-limit headers, and timeout settings. Do not increase concurrency to defeat limits.
- `UNSUPPORTED_SECURITY_CHALLENGE`: complete the site's intended manual flow; do not automate around it.
- Never log full request headers, commit populated secret files, or put credentials in a URL or command line.
