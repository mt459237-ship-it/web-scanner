# Automated Web Scanner

Python tool that audits websites for **missing/weak security headers** and **CORS misconfigurations**.

> Use only on sites you own or have written permission to test.

## Features
- Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Detects weak values (low HSTS max-age, unsafe-inline CSP) and info-leak headers (Server, X-Powered-By)
- CORS tests: reflected origin, `null` origin, wildcard + credentials, origin-spoofing, risky preflight methods
- Cookie flag audit (Secure, HttpOnly, SameSite)
- HTTP -> HTTPS redirect check
- Severity levels, 0-100 score and A-F grade
- Multi-target scan + JSON report export

## Install
```bash
pip install -r requirements.txt
```

## Usage
```bash
python scanner.py https://example.com
python scanner.py site1.com site2.com
python scanner.py -f targets.txt -o report.json
```

## Resume line
Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws, with severity scoring, cookie/HTTPS checks and JSON reporting.
