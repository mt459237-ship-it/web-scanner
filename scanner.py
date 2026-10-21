#!/usr/bin/env python3
"""
Automated Web Scanner
---------------------
Audits websites for missing/weak security headers and CORS misconfigurations.

Use ONLY on sites you own or have written permission to test.
"""

import argparse
import json
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()  # noqa

TIMEOUT = 10
USER_AGENT = "AutoWebScanner/1.0 (security-audit)"

# header -> (severity, description, recommendation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HIGH",
        "HSTS missing: browsers may allow downgrade to HTTP.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    "Content-Security-Policy": (
        "HIGH",
        "CSP missing: no defence-in-depth against XSS.",
        "Define a restrictive CSP, e.g. default-src 'self'",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "Clickjacking protection missing.",
        "Add: X-Frame-Options: DENY (or CSP frame-ancestors)",
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "MIME sniffing not disabled.",
        "Add: X-Content-Type-Options: nosniff",
    ),
    "Referrer-Policy": (
        "LOW",
        "Referrer policy missing: URLs may leak to third parties.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    "Permissions-Policy": (
        "LOW",
        "Permissions-Policy missing: browser features not restricted.",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    ),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def fetch(url, headers=None):
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=TIMEOUT,
                        allow_redirects=True, verify=True)


def check_security_headers(resp):
    findings = []
    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    for name, (sev, desc, fix) in SECURITY_HEADERS.items():
        if name.lower() not in hdrs:
            findings.append({"type": "missing_header", "header": name,
                             "severity": sev, "issue": desc, "fix": fix})

    # Weak value checks
    hsts = hdrs.get("strict-transport-security")
    if hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0])
            if age < 15768000:
                findings.append({"type": "weak_header",
                                 "header": "Strict-Transport-Security",
                                 "severity": "MEDIUM",
                                 "issue": f"HSTS max-age too low ({age}s).",
                                 "fix": "Use at least 31536000 (1 year)."})
        except (IndexError, ValueError):
            findings.append({"type": "weak_header",
                             "header": "Strict-Transport-Security",
                             "severity": "MEDIUM",
                             "issue": "HSTS has no valid max-age.",
                             "fix": "Add max-age=31536000"})

    csp = hdrs.get("content-security-policy", "")
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
        findings.append({"type": "weak_header",
                         "header": "Content-Security-Policy",
                         "severity": "MEDIUM",
                         "issue": "CSP allows unsafe-inline/unsafe-eval.",
                         "fix": "Use nonces or hashes instead."})

    for name in LEAKY_HEADERS:
        if name.lower() in hdrs:
            findings.append({"type": "info_leak", "header": name,
                             "severity": "INFO",
                             "issue": f"{name} reveals: {hdrs[name.lower()]}",
                             "fix": "Remove or genericise this header."})
    return findings


def check_cookies(resp):
    findings = []
    for c in resp.cookies:
        missing = []
        if not c.secure:
            missing.append("Secure")
        if not c.has_nonstandard_attr("HttpOnly"):
            missing.append("HttpOnly")
        if not (c.has_nonstandard_attr("SameSite")
                or c.has_nonstandard_attr("samesite")):
            missing.append("SameSite")
        if missing:
            findings.append({"type": "cookie", "header": f"Cookie: {c.name}",
                             "severity": "MEDIUM",
                             "issue": f"Missing flags: {', '.join(missing)}",
                             "fix": "Set Secure; HttpOnly; SameSite=Lax/Strict"})
    return findings


def check_cors(url):
    """Send requests with different Origin values and inspect the response."""
    findings = []
    parsed = urlparse(url)
    host = parsed.netloc

    test_origins = {
        "arbitrary": "https://evil-attacker.example",
        "null": "null",
        "subdomain_spoof": f"https://{host}.evil-attacker.example",
        "prefix_spoof": f"https://evil{host}",
    }

    for label, origin in test_origins.items():
        try:
            r = fetch(url, {"Origin": origin})
        except RequestException:
            continue

        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            continue

        if acao == origin and acac == "true":
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Origin",
                "severity": "CRITICAL",
                "issue": f"Reflects '{origin}' ({label}) WITH credentials=true.",
                "fix": "Use a strict allowlist; never reflect Origin with credentials."})
        elif acao == origin:
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Origin",
                "severity": "HIGH",
                "issue": f"Reflects arbitrary origin '{origin}' ({label}).",
                "fix": "Validate Origin against an allowlist."})
        elif acao == "*" and acac == "true":
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Origin",
                "severity": "HIGH",
                "issue": "Wildcard '*' combined with credentials=true.",
                "fix": "Browsers block this, but it signals a misconfiguration."})
        elif acao == "*" and label == "arbitrary":
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Origin",
                "severity": "LOW",
                "issue": "Wildcard '*' origin allowed (ok only for public data).",
                "fix": "Restrict to trusted origins if data is not public."})
        elif acao == "null":
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Origin",
                "severity": "HIGH",
                "issue": "'null' origin is trusted (exploitable via sandboxed iframes).",
                "fix": "Never allow the 'null' origin."})

    # Preflight check
    try:
        r = requests.options(
            url, timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT,
                     "Origin": "https://evil-attacker.example",
                     "Access-Control-Request-Method": "DELETE"})
        methods = r.headers.get("Access-Control-Allow-Methods", "")
        if (r.headers.get("Access-Control-Allow-Origin")
                in ("*", "https://evil-attacker.example")
                and any(m in methods.upper() for m in ("DELETE", "PUT", "PATCH"))):
            findings.append({
                "type": "cors", "header": "Access-Control-Allow-Methods",
                "severity": "MEDIUM",
                "issue": f"Preflight allows dangerous methods: {methods}",
                "fix": "Allow only the methods your API needs."})
    except RequestException:
        pass

    return findings


def check_https_redirect(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []
    http_url = url.replace("https://", "http://", 1)
    try:
        r = requests.get(http_url, timeout=TIMEOUT, allow_redirects=False,
                         headers={"User-Agent": USER_AGENT})
        loc = r.headers.get("Location", "")
        if not (300 <= r.status_code < 400 and loc.startswith("https://")):
            return [{"type": "transport", "header": "HTTP->HTTPS",
                     "severity": "HIGH",
                     "issue": "HTTP does not redirect to HTTPS.",
                     "fix": "Force a 301 redirect to HTTPS."}]
    except RequestException:
        pass
    return []


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SCORE_PENALTY = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


def grade(findings):
    score = max(0, 100 - sum(SCORE_PENALTY[f["severity"]] for f in findings))
    letter = ("A" if score >= 90 else "B" if score >= 75 else
              "C" if score >= 60 else "D" if score >= 40 else "F")
    return score, letter


def scan(url):
    url = normalize_url(url)
    result = {"url": url, "scanned_at": datetime.utcnow().isoformat() + "Z",
              "status": None, "findings": [], "error": None}
    try:
        resp = fetch(url)
    except RequestException as e:
        result["error"] = str(e)
        return result

    result["status"] = resp.status_code
    result["final_url"] = resp.url
    findings = []
    findings += check_security_headers(resp)
    findings += check_cookies(resp)
    findings += check_cors(resp.url)
    findings += check_https_redirect(resp.url)
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    result["findings"] = findings
    result["score"], result["grade"] = grade(findings)
    return result


COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
          "LOW": "\033[94m", "INFO": "\033[90m"}
RESET = "\033[0m"


def print_report(r):
    print("=" * 70)
    print(f"Target : {r['url']}")
    if r["error"]:
        print(f"ERROR  : {r['error']}")
        return
    print(f"Status : {r['status']}   Score: {r['score']}/100   Grade: {r['grade']}")
    print("-" * 70)
    if not r["findings"]:
        print("No issues found.")
    for f in r["findings"]:
        c = COLORS[f["severity"]]
        print(f"{c}[{f['severity']}]{RESET} {f['header']}")
        print(f"   Issue: {f['issue']}")
        print(f"   Fix  : {f['fix']}")


def main():
    p = argparse.ArgumentParser(
        description="Audit websites for security headers and CORS flaws.")
    p.add_argument("targets", nargs="*", help="URL(s) to scan")
    p.add_argument("-f", "--file", help="File with one URL per line")
    p.add_argument("-o", "--output", help="Save JSON report to this file")
    args = p.parse_args()

    targets = list(args.targets)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh
                        if l.strip() and not l.startswith("#")]
    if not targets:
        p.print_help()
        sys.exit(1)

    print("[!] Scan only sites you own or have permission to test.\n")
    results = []
    for t in targets:
        r = scan(t)
        print_report(r)
        results.append(r)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"\nJSON report saved to {args.output}")


if __name__ == "__main__":
    main()
