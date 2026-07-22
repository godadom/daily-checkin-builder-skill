# QingLong deployment

## Install or update the project

Use QingLong's subscription/repository feature to pull this repository into a panel-managed scripts directory, or upload the complete project directory through the panel. Keep the repository private when it contains operational metadata. Never add credentials to a repository URL, source file, task command, or subscription configuration.

Confirm the task container provides Python 3.11 or newer:

    python3 --version

From the project directory, install the pinned runtime dependencies and run the offline suite:

    python3 -m pip install --disable-pip-version-check -r requirements.txt
    python3 tests/run_offline.py

After each project update, pull or upload the new files, rerun the same dependency command, and rerun the offline suite before enabling the scheduled task.

## Configure the environment

Before deployment, put the verified non-secret origin and paths in `src/checkin/site_config.py` from an authorized, sanitized site analysis. Create QingLong environment variables from `.env.example` only for authentication and runtime choices: use `CHECKIN_ACCOUNTS` for multi-account secrets, or `CHECKIN_AUTH_TYPE` plus `CHECKIN_TOKEN`, `CHECKIN_COOKIE`, or `CHECKIN_API_KEY` for one account. The application rejects `CHECKIN_BASE_URL`, `CHECKIN_STATUS_PATH`, and `CHECKIN_ACTION_PATH` overrides. Store secrets only in QingLong's protected environment-variable store, disable any value that is no longer used, and never paste secrets into logs or commands.

Set `CHECKIN_TIMEZONE` to the same IANA zone used by the panel scheduler. `CHECKIN_NOTIFY_MODE=log` enables the built-in redacted stdout summary; `CHECKIN_NOTIFY_MODE=off` disables that summary. No external notification sender is bundled. Add one only as an explicit, environment-configured adapter that receives the already-redacted summary; notification failure must not alter the check-in exit status.

## Create and test the task

Create one serial task:

- Command: `cd /ql/data/scripts/authorized-daily-checkin && python3 run.py`
- Recommended cron: `23 8 * * *`
- Concurrency: one instance
- Timeout: 10 minutes or the panel's nearest equivalent

Adjust the project path to the actual panel directory. Minute 23 avoids the top-of-hour peak. The cron uses the panel's timezone, so verify that setting separately from `CHECKIN_TIMEZONE`.

Before enabling the schedule, run these commands manually in the task directory:

    python3 tests/run_offline.py
    python3 run.py

The first command is fully offline. The second is a live authorized run and must be used only after the protected environment values are configured.

If verified `docs/cookie-setup.md` selects `password_login`, `otp_login`, or `interactive_login`, run the generated companion command on the operator's desktop, for example `python login.py --ui headed --store qinglong`. Do not create a QingLong login task or assign cron to this command. The local helper opens the ordinary site login page, keeps one browser context while the operator enters credentials/OTP and completes human verification, then sends only the whitelisted cookie to the configured QingLong instance through a verified OpenAPI. Keep the QingLong base URL, Client ID, and Client Secret in protected local environment variables; never pass them or the cookie on the command line or print them. If the local machine cannot reach the OpenAPI, follow the generated site-specific instructions to paste the resulting value directly into the named QingLong environment-variable field. QingLong installs and runs only the HTTP check-in dependencies, not an interactive browser stack.

## Operate, rotate, and disable

When authentication expires, complete the site's ordinary login flow manually, replace the affected QingLong environment value, and manually rerun the task. Do not automate login, CAPTCHA, WAF, WebAuthn, or device-verification challenges.

To stop automation, disable the task and its related environment values in the panel. To retire it, remove the task first, then remove the project directory and protected values through normal panel controls. Do not leave an active cron pointing to a deleted or stale checkout.

## Troubleshoot by state

| State / exit | Operator action |
| --- | --- |
| `SUCCESS` / `ALREADY_DONE` / `0` | No action; confirm the redacted account summary only. |
| `CONFIG_ERROR` / `2` | Check missing variables, JSON shape, HTTPS origin, endpoint paths, IANA timezone, and notification mode. |
| `AUTH_EXPIRED` / `3` | Refresh only the affected credential through the normal login flow, then replace the protected value. |
| `TEMPORARY_ERROR` / `4` | Check panel connectivity and site status; keep retries bounded and wait before a manual rerun. |
| `SITE_CHANGED` / `5` | Disable the task, collect a newly sanitized response sample, update the documented contract and offline tests, then redeploy. |
| `UNSUPPORTED_SECURITY_CHALLENGE` / `6` | Disable automation for that flow and handle the challenge manually; do not bypass it. |
| `ACCESS_DENIED` / `7` | Disable the task and verify account entitlement or policy; do not retry or bypass access controls. |
| `INTERNAL_ERROR` / `70` | Review only redacted logs, reproduce with offline tests, and fix the implementation without exposing secrets. |

Mixed failures use this priority: access denied, security challenge, configuration, site change, authentication, temporary failure, then internal error. All accounts still receive a result before the process exits.
