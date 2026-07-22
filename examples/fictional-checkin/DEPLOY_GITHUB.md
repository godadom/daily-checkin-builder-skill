# GitHub Actions deployment

The fictional `docs/cookie-setup.md` selects `not_applicable`; configure its bearer token directly as a protected Secret. A real password/OTP Cookie-login project must run its visible browser helper locally and must not run interactive login in the scheduled workflow.

1. In repository Settings, create Actions secret `CHECKIN_ACCOUNTS` using the JSON format in `README.md`. For a single account, a one-item array is recommended.
2. The verified, non-secret origin and endpoint paths are already in `src/checkin/site_config.py`; do not create repository variables for them. Optionally set `CHECKIN_WRITE_JOB_SUMMARY=true` to enable the credential-free job-summary notification step; omit it or set it to `false` to disable that step.
3. Open Actions, select **Daily check-in**, and use **Run workflow**. The job runs offline tests before the check-in.
4. Inspect only the redacted result lines. Refresh an expired secret by replacing it in Settings; never print it for diagnosis.

The example schedule uses `cron: "17 7 * * *"` with `timezone: "Asia/Shanghai"`; minute 17 avoids the top-of-hour peak. To change it, edit both the schedule's IANA `timezone` and the job-level `CHECKIN_TIMEZONE`, then run the workflow manually. Daylight-saving transitions can skip or repeat a local wall-clock time, so keep the already-done check enabled. Scheduled workflows run only from the default branch, the workflow file must exist there, jobs can be delayed under load, and GitHub may disable schedules in long-inactive public repositories.

The workflow uses read-only repository permission, a concurrency group, a ten-minute timeout, explicit Python/runner versions, dependency caching, and a nonzero application exit on failure. Official actions are pinned to audited commit SHAs with release comments. The optional job-summary step runs after the application with `always()` and cannot change its exit status; it contains no account details. Application exit codes are `2` config, `3` auth, `4` temporary, `5` site change, `6` unsupported challenge, and `70` internal; the job preserves these codes.

To disable automation, disable the workflow in Actions or remove/comment its `schedule` trigger. Manual dispatch can remain available. Fork and pull-request workflows receive no live-test switch and should not be given production secrets.
