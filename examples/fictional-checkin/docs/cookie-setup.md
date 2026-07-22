# Example Rewards authentication setup

- Acquisition mode: `not_applicable`
- Site and scope: `https://rewards.example.invalid/`, reserved fictional evidence only
- Evidence source: `docs/sanitized-evidence.md` observes bearer authentication and no Cookie-authenticated request or login flow

## Exact operator steps

No Network extraction, Console expression, or interactive Cookie login is applicable. Configure the fictional bearer credential only through the protected `CHECKIN_TOKEN` or `CHECKIN_ACCOUNTS` environment variable described in the README.

## Output and transformation

There is no Cookie string to build or transform. Cookie support in the reusable runtime is not evidence that this fictional site uses it.

## Secret destination

Use the selected platform's protected bearer-token Secret. Do not add `CHECKIN_COOKIE` for this example.

## Expiration and renewal

An evidenced authentication-expiry response becomes `AUTH_EXPIRED`. Replace the bearer token through the site's documented normal process; this fictional example defines no real renewal endpoint.
