# Security policy

Never commit real cookies, authorization headers, passwords, tokens, API keys, phone numbers, email addresses, device identifiers, or personal response data. Before sharing an issue, rotate any credential that may have appeared, replace values with consistent placeholders, remove query secrets, sanitize HAR request/response bodies, and verify the final archive with a text search.

Report a sanitized problem privately to the project maintainer through the repository's security-advisory channel. Include state transitions, HTTP status classes, redacted response shape, and a minimal mock fixture. Do not attach a populated `.env`, raw HAR, browser profile, or full headers.

This project will not extract another person's credentials, brute-force authentication, bypass CAPTCHA/WAF/Turnstile/WebAuthn/device or SMS verification, evade access control, conceal scraping, mass-register accounts, or exploit reward systems. Encountering such a control produces `UNSUPPORTED_SECURITY_CHALLENGE` or requires manual handling.

The logger masks common secret keys, custom sensitive fields, configured secret values, and exception text. This is defense in depth: callers must still avoid logging raw headers or secret-bearing objects.
