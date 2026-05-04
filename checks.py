"""
checks.py — Tier 1 professional detection engine
Fixes applied:
  - A01: 403-bypass finding + LOW finding both emitted on bypass success. Fixed with
    explicit `found_bypass` flag so only one finding is appended per path.
  - A02: includeSubDomains check fired on HTTP sites (nonsensical). Guarded with
    parsed.scheme == "https".
  - A03: check_injection() fetched base URL twice (wasteful, discarded first response).
    Cached into `r_base` at top and reused in passive block.
  - A03: SQLi/XSS inner `break` only escaped payload loop, allowing duplicate findings
    per param across multiple payloads. Now uses a `confirmed_params` set to emit
    at most one finding per (param, check-type) pair.
  - A03: fake CVE "CVE-2024-GENERIC-SQLI" replaced with a real CVE list keyed by
    DB error signature (MySQL, Postgres, SQLite, Oracle, MSSQL).
  - A06: jQuery loop broke after first src match even when no vuln entry was found,
    silently skipping subsequent scripts. Fixed: only break when a vuln was recorded.
  - General: all checks are fully type-annotated and clearly commented.
"""

import requests
import re
import time
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
import urllib3

urllib3.disable_warnings()

log = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnScanner/2.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 12


# ═══════════════════════════════════════════════════════════
# HTTP helpers
# ═══════════════════════════════════════════════════════════

def _format_request(method: str, url: str, headers: dict = None, body: str = None) -> str:
    parsed = urlparse(url)
    path   = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for k, v in (headers or HEADERS).items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append(f"\n{body}")
    return "\n".join(lines)


def _format_response(r) -> str:
    if r is None:
        return "No response (connection error or timeout)"
    lines = [f"HTTP/1.1 {r.status_code} {r.reason}"]
    for k, v in r.headers.items():
        lines.append(f"{k}: {v}")
    body_preview = r.text[:800] if r.text else ""
    if body_preview:
        lines.append(f"\n{body_preview}")
        if len(r.text) > 800:
            lines.append(f"\n... [{len(r.text) - 800} bytes truncated]")
    return "\n".join(lines)


# Delay between requests in active mode to avoid IP bans (seconds)
ACTIVE_RATE_LIMIT = 0.5
PASSIVE_RATE_LIMIT = 0.1

def safe_get(url: str, extra_headers: dict = None, mode: str = "passive", **kwargs):
    time.sleep(ACTIVE_RATE_LIMIT if mode == "active" else PASSIVE_RATE_LIMIT)
    h = {**HEADERS, **(extra_headers or {})}
    try:
        return requests.get(url, headers=h, timeout=TIMEOUT,
                            verify=False, allow_redirects=True, **kwargs)
    except Exception as exc:
        log.debug("safe_get(%s) failed: %s", url, exc)
        return None


def safe_post(url: str, data=None, json=None, extra_headers: dict = None, mode: str = "passive", **kwargs):
    time.sleep(ACTIVE_RATE_LIMIT if mode == "active" else PASSIVE_RATE_LIMIT)
    h = {**HEADERS, **(extra_headers or {})}
    try:
        return requests.post(url, headers=h, data=data, json=json,
                             timeout=TIMEOUT, verify=False,
                             allow_redirects=True, **kwargs)
    except Exception as exc:
        log.debug("safe_post(%s) failed: %s", url, exc)
        return None

# ═══════════════════════════════════════════════════════════
# Canonical finding builder
# ═══════════════════════════════════════════════════════════

def finding(
    check_name: str,
    title: str,
    severity: str,
    owasp: str,
    cwe: str,
    cvss: float,
    detail: str,
    fix: str,
    url: str,
    confidence: int,
    signals: list,
    evidence_req: str = None,
    evidence_res: str = None,
    cve: list = None,
    mode: str = "passive",
) -> dict:
    return {
        "check":      check_name,
        "type":       title,
        "severity":   severity,
        "owasp":      owasp,
        "cwe":        cwe,
        "cvss":       cvss,
        "cve":        cve or [],
        "url":        url,
        "detail":     detail,
        "fix":        fix,
        "confidence": min(max(confidence, 0), 100),
        "signals":    signals,
        "mode":       mode,
        "triage":     "Unreviewed",
        "evidence": {
            "request":  evidence_req or "",
            "response": evidence_res or "",
        },
    }


# ═══════════════════════════════════════════════════════════
# A01 — Broken Access Control
# ═══════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    ("/admin",            "Admin panel"),
    ("/admin/",           "Admin panel"),
    ("/administrator",    "Administrator panel"),
    ("/wp-admin",         "WordPress admin"),
    ("/dashboard",        "Dashboard"),
    ("/panel",            "Control panel"),
    ("/api/admin",        "Admin API"),
    ("/api/users",        "Users API"),
    ("/api/config",       "Config API"),
    ("/.git/HEAD",        "Git repository"),
    ("/.env",             "Environment file"),
    ("/config.php",       "PHP config"),
    ("/wp-config.php",    "WordPress config"),
    ("/backup",           "Backup directory"),
    ("/phpmyadmin",       "phpMyAdmin"),
    ("/server-status",    "Apache server status"),
    ("/actuator",         "Spring Boot actuator"),
    ("/actuator/env",     "Spring Boot env endpoint"),
    ("/swagger-ui.html",  "Swagger UI"),
    ("/api-docs",         "API documentation"),
    ("/graphql",          "GraphQL endpoint"),
]

ADMIN_BODY_SIGNALS = [
    "log out", "logout", "sign out", "admin", "dashboard",
    "welcome back", "manage users", "control panel", "settings",
]

SENSITIVE_CONTENT_SIGNALS = [
    "db_password", "db_pass", "secret_key", "api_key",
    "aws_access", "aws_secret", "private_key",
    "root:", "/bin/bash", "[database]",
]


def check_broken_access_control(url: str, mode: str = "passive") -> list:
    findings = []

    for path, label in SENSITIVE_PATHS:
        target  = urljoin(url, path)
        r       = safe_get(target)
        req_str = _format_request("GET", target)
        res_str = _format_response(r)

        if r is None:
            continue

        # ── HTTP 200 ─────────────────────────────────────────
        if r.status_code == 200:
            signals    = [f"HTTP 200 returned for {path}"]
            confidence = 40
            body_lower = r.text.lower()

            matched_body = [s for s in ADMIN_BODY_SIGNALS if s in body_lower]
            if matched_body:
                signals.append(f"Body contains admin keywords: {', '.join(matched_body[:3])}")
                confidence += 30

            matched_content = [s for s in SENSITIVE_CONTENT_SIGNALS if s in body_lower]
            if matched_content:
                signals.append(f"Sensitive content found: {', '.join(matched_content[:3])}")
                confidence += 25

            if len(r.text) > 500:
                signals.append(f"Substantial response body ({len(r.text)} bytes)")
                confidence += 5

            if confidence < 50:
                sev, cvss_score = "INFO",     3.1
            elif confidence < 70:
                sev, cvss_score = "MEDIUM",   6.5
            else:
                sev, cvss_score = "CRITICAL", 9.1

            findings.append(finding(
                check_name="A01 — Broken Access Control",
                title="Sensitive Path Accessible",
                severity=sev,
                owasp="A01:2021",
                cwe="CWE-284",
                cvss=cvss_score,
                detail=f"{label} ({path}) returned HTTP 200 without authentication.",
                fix="Implement authentication and authorisation on all sensitive endpoints. "
                    "Return HTTP 401/403 for unauthenticated requests.",
                url=target,
                confidence=confidence,
                signals=signals,
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

        # ── HTTP 403 — probe for bypass ───────────────────────
        elif r.status_code == 403:
            base_signals = [f"HTTP 403 — path exists, access denied: {path}"]

            # FIX: previously, both the bypass finding AND the LOW 403 finding were
            # appended when bypass succeeded, because `continue` was inside the
            # `if mode == "active"` block and didn't prevent the LOW append below.
            # Now controlled by `found_bypass` flag.
            found_bypass = False

            if mode == "active":
                bypass_headers = {"X-Original-URL": path, "X-Rewrite-URL": path}
                r2 = safe_get(target, extra_headers=bypass_headers)
                if r2 and r2.status_code == 200:
                    bypass_signals = base_signals + ["403 bypassed using X-Original-URL header"]
                    findings.append(finding(
                        check_name="A01 — Broken Access Control",
                        title="403 Bypass via Header Manipulation",
                        severity="HIGH",
                        owasp="A01:2021",
                        cwe="CWE-863",
                        cvss=8.2,
                        detail=f"{path} returns 403 normally but 200 with X-Original-URL header injection.",
                        fix="Enforce access control at the application layer, not only at the proxy. "
                            "Reject X-Original-URL and X-Rewrite-URL from untrusted clients.",
                        url=target,
                        confidence=90,
                        signals=bypass_signals,
                        evidence_req=_format_request("GET", target, {**HEADERS, **bypass_headers}),
                        evidence_res=_format_response(r2),
                        mode="active",
                    ))
                    found_bypass = True

            # Only append the LOW informational finding if bypass was NOT confirmed.
            if not found_bypass:
                findings.append(finding(
                    check_name="A01 — Broken Access Control",
                    title="Restricted Path Exists (403)",
                    severity="LOW",
                    owasp="A01:2021",
                    cwe="CWE-284",
                    cvss=3.1,
                    detail=f"{label} ({path}) exists and returns 403. Manual bypass testing recommended.",
                    fix="Verify 403 cannot be bypassed with header manipulation "
                        "(X-Original-URL, X-Forwarded-For, X-Rewrite-URL).",
                    url=target,
                    confidence=30,
                    signals=base_signals,
                    evidence_req=req_str,
                    evidence_res=res_str,
                    mode="passive",
                ))

    return findings


# ═══════════════════════════════════════════════════════════
# A02 — Cryptographic Failures
# ═══════════════════════════════════════════════════════════

def check_cryptographic_failures(url: str, mode: str = "passive") -> list:
    findings = []
    parsed   = urlparse(url)
    r        = safe_get(url)
    req_str  = _format_request("GET", url)
    res_str  = _format_response(r)

    # ── Plaintext HTTP ────────────────────────────────────────
    if parsed.scheme == "http":
        signals   = ["URL scheme is HTTP — no TLS encryption"]
        https_url = url.replace("http://", "https://", 1)
        r_https   = safe_get(https_url)
        if r_https and r_https.status_code in (200, 301, 302):
            signals.append("HTTPS version exists but redirect not enforced from HTTP")
        else:
            signals.append("HTTPS version unreachable — no upgrade path")

        findings.append(finding(
            check_name="A02 — Cryptographic Failures",
            title="Plaintext HTTP — No TLS",
            severity="HIGH",
            owasp="A02:2021",
            cwe="CWE-319",
            cvss=7.5,
            detail="Site served over HTTP. Credentials, session tokens, and data transmitted in cleartext.",
            fix="Enable HTTPS with TLS 1.2/1.3. Redirect all HTTP to HTTPS. Add HSTS.",
            url=url,
            confidence=98,
            signals=signals,
            evidence_req=req_str,
            evidence_res=res_str,
            mode="passive",
        ))

    if not r:
        return findings

    headers = {k.lower(): v for k, v in r.headers.items()}

    # ── HSTS ──────────────────────────────────────────────────
    if parsed.scheme == "https":
        if "strict-transport-security" not in headers:
            findings.append(finding(
                check_name="A02 — Cryptographic Failures",
                title="Missing HSTS Header",
                severity="MEDIUM",
                owasp="A02:2021",
                cwe="CWE-523",
                cvss=5.9,
                detail="Strict-Transport-Security absent. Browsers may downgrade to HTTP, enabling MITM.",
                fix="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                url=url,
                confidence=85,
                signals=["Strict-Transport-Security header absent from HTTPS response"],
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))
        else:
            hsts_val  = headers["strict-transport-security"]
            age_match = re.search(r"max-age=(\d+)", hsts_val)

            if age_match and int(age_match.group(1)) < 31536000:
                findings.append(finding(
                    check_name="A02 — Cryptographic Failures",
                    title="Weak HSTS max-age",
                    severity="LOW",
                    owasp="A02:2021",
                    cwe="CWE-523",
                    cvss=3.7,
                    detail=f"HSTS max-age={age_match.group(1)} is below recommended 31536000 (1 year).",
                    fix="Set max-age=31536000; includeSubDomains; preload",
                    url=url,
                    confidence=88,
                    signals=[f"HSTS max-age={age_match.group(1)} < 31536000"],
                    evidence_req=req_str,
                    evidence_res=res_str,
                    mode="passive",
                ))

            # FIX: this check previously ran on HTTP sites too (nonsensical).
            # Now guarded inside the `parsed.scheme == "https"` block.
            if "includesubdomains" not in hsts_val.lower():
                findings.append(finding(
                    check_name="A02 — Cryptographic Failures",
                    title="HSTS Missing includeSubDomains",
                    severity="LOW",
                    owasp="A02:2021",
                    cwe="CWE-523",
                    cvss=3.1,
                    detail="HSTS header lacks includeSubDomains — subdomains vulnerable to downgrade attacks.",
                    fix="Add includeSubDomains to your HSTS header.",
                    url=url,
                    confidence=85,
                    signals=["includeSubDomains directive absent from HSTS"],
                    evidence_req=req_str,
                    evidence_res=res_str,
                    mode="passive",
                ))

    # ── Cookie security ───────────────────────────────────────
    set_cookie_headers = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
    for cookie_val in set_cookie_headers:
        cookie_name = cookie_val.split("=")[0].strip()
        cookie_lower = cookie_val.lower()
        is_session   = any(s in cookie_name.lower()
                           for s in ["session", "sess", "auth", "token", "jwt", "sid"])

        if "secure" not in cookie_lower and parsed.scheme == "https":
            findings.append(finding(
                check_name="A02 — Cryptographic Failures",
                title="Cookie Missing Secure Flag",
                severity="MEDIUM" if is_session else "LOW",
                owasp="A02:2021",
                cwe="CWE-614",
                cvss=5.3 if is_session else 3.1,
                detail=f"Cookie '{cookie_name}' lacks Secure flag — may transmit over HTTP.",
                fix="Add Secure flag to all cookies, especially session cookies.",
                url=url,
                confidence=88 if is_session else 60,
                signals=[f"Secure flag absent on cookie: {cookie_name}"],
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

        if "httponly" not in cookie_lower and is_session:
            findings.append(finding(
                check_name="A02 — Cryptographic Failures",
                title="Session Cookie Missing HttpOnly",
                severity="MEDIUM",
                owasp="A02:2021",
                cwe="CWE-1004",
                cvss=5.3,
                detail=f"Session cookie '{cookie_name}' accessible via JavaScript. XSS can steal it.",
                fix="Add HttpOnly flag to all session cookies.",
                url=url,
                confidence=85,
                signals=[f"HttpOnly absent on session cookie: {cookie_name}"],
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

        if "samesite" not in cookie_lower and is_session:
            findings.append(finding(
                check_name="A02 — Cryptographic Failures",
                title="Session Cookie Missing SameSite",
                severity="LOW",
                owasp="A02:2021",
                cwe="CWE-352",
                cvss=4.3,
                detail=f"Cookie '{cookie_name}' lacks SameSite attribute — increases CSRF surface.",
                fix="Add SameSite=Strict or SameSite=Lax to session cookies.",
                url=url,
                confidence=75,
                signals=[f"SameSite absent on session cookie: {cookie_name}"],
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

    return findings


# ═══════════════════════════════════════════════════════════
# A03 — Injection
# ═══════════════════════════════════════════════════════════

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "pg_query(): query failed",
    "sqlite_query",
    "odbc sql server driver",
    "syntax error or access violation",
    "supplied argument is not a valid mysql",
]

# FIX: was a single fake CVE "CVE-2024-GENERIC-SQLI".
# Real CVEs mapped per DB engine signature.
SQLI_CVE_MAP = {
    "warning: mysql":                      ["CVE-2012-5615", "CVE-2008-2079"],
    "you have an error in your sql syntax": ["CVE-2012-5615"],
    "pg_query(): query failed":            ["CVE-2019-10164"],
    "sqlite_query":                        ["CVE-2019-5018"],
    "ora-01756":                           ["CVE-2012-1675"],
    "odbc sql server driver":              ["CVE-2008-0085"],
}

SQL_PAYLOADS = [
    ("'",          SQLI_ERROR_SIGNATURES),
    ("1 OR 1=1--", SQLI_ERROR_SIGNATURES),
    ("' OR ''='",  SQLI_ERROR_SIGNATURES),
]

XSS_PAYLOADS = [
    '<script>alert("xss")</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
]


def check_injection(url: str, mode: str = "passive") -> list:
    findings    = []
    parsed      = urlparse(url)

    # FIX: was fetching url twice (once in active block, once below for passive).
    # Cache a single base response and reuse it in the passive block.
    r_base     = safe_get(url)
    req_base   = _format_request("GET", url)
    res_base   = _format_response(r_base)

    if mode == "active" and parsed.query:
        params   = parse_qs(parsed.query, keep_blank_values=True)
        base_url = url.split("?")[0]

        # FIX: was using `break` only on inner payload loop, allowing multiple
        # findings per param across payloads. Now uses confirmed_sqli_params /
        # confirmed_xss_params sets so at most one finding per (param, type).
        confirmed_sqli_params = set()
        confirmed_xss_params  = set()

        # ── SQL Injection ─────────────────────────────────────
        for param in params:
            if param in confirmed_sqli_params:
                continue
            for payload, error_patterns in SQL_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = base_url + "?" + urlencode(test_params)
                req_str  = _format_request("GET", test_url)
                r        = safe_get(test_url)
                res_str  = _format_response(r)

                if not r:
                    continue

                body_lower = r.text.lower()
                matched    = [sig for sig in error_patterns if sig in body_lower]
                if not matched:
                    continue

                # Resolve real CVEs from matched signatures
                cve_list = []
                for sig in matched:
                    cve_list.extend(SQLI_CVE_MAP.get(sig, []))
                cve_list = sorted(set(cve_list))

                findings.append(finding(
                    check_name="A03 — Injection",
                    title="SQL Injection (Error-Based)",
                    severity="CRITICAL",
                    owasp="A03:2021",
                    cwe="CWE-89",
                    cvss=9.8,
                    detail=f"SQL error triggered in parameter '{param}' with payload: {payload}. "
                           f"Error signatures: {', '.join(matched[:3])}",
                    fix="Use parameterised queries exclusively. "
                        "Never concatenate user input into SQL strings. "
                        "Apply input validation and least-privilege DB accounts.",
                    url=test_url,
                    confidence=min(50 + len(matched) * 15, 97),
                    signals=[
                        f"Parameter: {param}",
                        f"Payload: {payload}",
                        f"Error signatures matched: {', '.join(matched[:2])}",
                    ],
                    evidence_req=req_str,
                    evidence_res=res_str,
                    cve=cve_list,
                    mode="active",
                ))
                confirmed_sqli_params.add(param)
                break   # Stop trying more payloads for this param — confirmed

        # ── Reflected XSS ─────────────────────────────────────
        for param in params:
            if param in confirmed_xss_params:
                continue
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = base_url + "?" + urlencode(test_params)
                req_str  = _format_request("GET", test_url)
                r        = safe_get(test_url)
                res_str  = _format_response(r)

                if not r:
                    continue

                signals    = []
                confidence = 0

                if payload in r.text:
                    signals.append("Payload reflected verbatim in response body")
                    confidence += 60

                encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                if encoded not in r.text and payload in r.text:
                    signals.append("Payload NOT HTML-encoded — likely executable in browser")
                    confidence += 25

                if "text/html" in r.headers.get("content-type", ""):
                    signals.append("Content-Type: text/html — browser will render payload")
                    confidence += 10

                if "content-security-policy" not in {k.lower() for k in r.headers}:
                    signals.append("No CSP header to block script execution")
                    confidence += 5

                if confidence >= 70:
                    findings.append(finding(
                        check_name="A03 — Injection",
                        title="Reflected XSS",
                        severity="HIGH",
                        owasp="A03:2021",
                        cwe="CWE-79",
                        cvss=7.2,
                        detail=f"XSS payload reflected unencoded in parameter '{param}'. "
                               "An attacker can inject arbitrary JavaScript into victim browsers.",
                        fix="HTML-encode all user-controlled output. "
                            "Implement a strict Content-Security-Policy. "
                            "Use framework-level auto-escaping.",
                        url=test_url,
                        confidence=min(confidence, 97),
                        signals=signals,
                        evidence_req=req_str,
                        evidence_res=res_str,
                        mode="active",
                    ))
                    confirmed_xss_params.add(param)
                    break   # Stop trying more payloads for this param — confirmed

    # ── Passive: injection surface detection ──────────────────
    # FIX: was fetching url a second time here. Now reuses r_base.
    if r_base:
        soup       = BeautifulSoup(r_base.text, "html.parser")
        forms      = soup.find_all("form")
        injectable = [
            f for f in forms
            if f.find_all("input", {"type": lambda t: t not in ["hidden", "submit", "button", None]})
        ]
        if injectable:
            findings.append(finding(
                check_name="A03 — Injection",
                title="Injection Surface Identified (Forms)",
                severity="INFO",
                owasp="A03:2021",
                cwe="CWE-20",
                cvss=0.0,
                detail=f"{len(injectable)} form(s) with user-input fields detected. "
                       "Candidate surfaces for SQLi, XSS, command injection. "
                       "Enable active mode to probe automatically.",
                fix="Validate all inputs server-side. Use parameterised queries. Encode all output.",
                url=url,
                confidence=95,
                signals=[f"{len(injectable)} injectable form(s) detected"],
                evidence_req=req_base,
                evidence_res=res_base,
                mode="passive",
            ))

    return findings


# ═══════════════════════════════════════════════════════════
# A05 — Security Misconfiguration
# ═══════════════════════════════════════════════════════════

SECURITY_HEADERS = [
    ("content-security-policy",  "HIGH",   "CWE-693", 6.1,
     "Content-Security-Policy (CSP) missing — XSS and data injection not mitigated by browser.",
     "Implement CSP: Content-Security-Policy: default-src 'self'"),

    ("x-frame-options",          "MEDIUM", "CWE-1021", 6.1,
     "X-Frame-Options missing — site may be embeddable in iframes (clickjacking risk).",
     "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive."),

    ("x-content-type-options",   "LOW",    "CWE-16", 4.3,
     "X-Content-Type-Options: nosniff missing — MIME-sniffing attacks possible.",
     "Add: X-Content-Type-Options: nosniff"),

    ("referrer-policy",          "LOW",    "CWE-16", 3.1,
     "Referrer-Policy missing — URL data may leak in Referer headers.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),

    ("permissions-policy",       "LOW",    "CWE-16", 2.7,
     "Permissions-Policy missing — browser APIs (camera, microphone, geolocation) not restricted.",
     "Add Permissions-Policy to restrict unnecessary browser feature access."),
]


def check_security_misconfiguration(url: str, mode: str = "passive") -> list:
    findings = []
    r        = safe_get(url)
    req_str  = _format_request("GET", url)
    res_str  = _format_response(r)

    if not r:
        return findings

    headers = {k.lower(): v for k, v in r.headers.items()}

    # ── Missing security headers ──────────────────────────────
    for header, severity, cwe, cvss, detail, fix in SECURITY_HEADERS:
        if header not in headers:
            signals    = [f"{header} header absent from response"]
            confidence = 80

            if header == "content-security-policy":
                soup   = BeautifulSoup(r.text, "html.parser")
                inline = soup.find_all("script", src=False)
                if inline:
                    signals.append(f"{len(inline)} inline <script> block(s) present — CSP would restrict these")
                    confidence = 90

            findings.append(finding(
                check_name="A05 — Security Misconfiguration",
                title=f"Missing {header.title()} Header",
                severity=severity,
                owasp="A05:2021",
                cwe=cwe,
                cvss=cvss,
                detail=detail,
                fix=fix,
                url=url,
                confidence=confidence,
                signals=signals,
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

    # ── Technology / version disclosure ───────────────────────
    for disc_header in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
        if disc_header in headers:
            val        = headers[disc_header]
            confidence = 88 if re.search(r"\d+\.\d+", val) else 75
            signals    = [
                f"{disc_header}: {val}",
                "Technology stack disclosed — aids targeted CVE exploitation",
            ]
            ver_match = re.search(r"\d+\.\d+[\.\d]*", val)
            if ver_match:
                signals.append(f"Version number disclosed: {ver_match.group()}")

            findings.append(finding(
                check_name="A05 — Security Misconfiguration",
                title="Technology/Version Disclosure via Response Header",
                severity="LOW",
                owasp="A05:2021",
                cwe="CWE-200",
                cvss=5.3,
                detail=f"Header '{disc_header}' discloses: {val}. Aids attackers targeting known CVEs.",
                fix=f"Remove or sanitise the {disc_header} header in your server/application config.",
                url=url,
                confidence=confidence,
                signals=signals,
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

    # ── CORS misconfiguration (active) ────────────────────────
    if mode == "active":
        test_origin = "https://evil.attacker.com"
        r_cors      = safe_get(url, extra_headers={"Origin": test_origin})
        if r_cors:
            acao = r_cors.headers.get("Access-Control-Allow-Origin", "")
            acac = r_cors.headers.get("Access-Control-Allow-Credentials", "")

            if acao == test_origin:
                has_creds = acac.lower() == "true"
                signals   = [
                    f"Attacker-controlled origin reflected: Access-Control-Allow-Origin: {acao}",
                    "Access-Control-Allow-Credentials: true — credentials cross-origin" if has_creds
                    else "No credentials flag, but origin reflection is still exploitable",
                ]
                findings.append(finding(
                    check_name="A05 — Security Misconfiguration",
                    title="CORS — Arbitrary Origin Reflected",
                    severity="CRITICAL" if has_creds else "HIGH",
                    owasp="A05:2021",
                    cwe="CWE-942",
                    cvss=9.0 if has_creds else 8.1,
                    detail="Server reflects attacker-controlled Origin header. "
                           + ("Credentials permitted cross-origin — full session read possible."
                              if has_creds else "No credentials currently, but still exploitable."),
                    fix="Maintain an explicit origin allowlist. "
                        "Never echo the Origin header directly. "
                        "Never combine wildcard ACAO with ACAC: true.",
                    url=url,
                    confidence=95 if has_creds else 90,
                    signals=signals,
                    evidence_req=_format_request("GET", url, {**HEADERS, "Origin": test_origin}),
                    evidence_res=_format_response(r_cors),
                    mode="active",
                ))

            elif acao == "*":
                findings.append(finding(
                    check_name="A05 — Security Misconfiguration",
                    title="CORS Wildcard Origin",
                    severity="MEDIUM",
                    owasp="A05:2021",
                    cwe="CWE-942",
                    cvss=5.4,
                    detail="Access-Control-Allow-Origin: * permits any origin to read responses. "
                           "Dangerous for authenticated resources.",
                    fix="Replace wildcard with an explicit origin allowlist. "
                        "Never use wildcard with cookies or credentials.",
                    url=url,
                    confidence=85,
                    signals=["Access-Control-Allow-Origin: * (wildcard)"],
                    evidence_req=_format_request("GET", url, {**HEADERS, "Origin": test_origin}),
                    evidence_res=_format_response(r_cors),
                    mode="active",
                ))

    # ── Directory listing ─────────────────────────────────────
    body_lower    = r.text.lower()
    dir_signals   = []
    dir_confidence = 0

    if "index of /" in body_lower:
        dir_signals.append('"Index of /" found in response body')
        dir_confidence += 65
    if "parent directory" in body_lower or ("href" in body_lower and "../" in r.text):
        dir_signals.append("Parent directory navigation link present")
        dir_confidence += 30

    if dir_confidence >= 60:
        findings.append(finding(
            check_name="A05 — Security Misconfiguration",
            title="Directory Listing Enabled",
            severity="MEDIUM",
            owasp="A05:2021",
            cwe="CWE-548",
            cvss=5.3,
            detail="Web server returns a directory listing — exposes file names, paths, and backup files.",
            fix="Disable directory listing: Options -Indexes (Apache) / autoindex off (Nginx).",
            url=url,
            confidence=min(dir_confidence, 95),
            signals=dir_signals,
            evidence_req=req_str,
            evidence_res=res_str,
            mode="passive",
        ))

    return findings


# ═══════════════════════════════════════════════════════════
# A06 — Vulnerable and Outdated Components
# ═══════════════════════════════════════════════════════════

JQUERY_VULNS = {
    # (max_major, max_minor): (severity, real_cves, description)
    (1, 99): ("CRITICAL", ["CVE-2019-11358", "CVE-2015-9251", "CVE-2011-4969"],
              "jQuery 1.x — multiple critical XSS and prototype pollution CVEs"),
    (2, 99): ("HIGH",     ["CVE-2019-11358"],
              "jQuery 2.x — prototype pollution (CVE-2019-11358)"),
    (3, 4):  ("HIGH",     ["CVE-2020-11022", "CVE-2020-11023"],
              "jQuery < 3.5 — XSS via HTML manipulation (CVE-2020-11022/23)"),
}

LIBRARY_PATTERNS = [
    (r"bootstrap[.\-/](\d+\.\d+)", "Bootstrap", "5.0",
     ["CVE-2019-8331", "CVE-2018-14041"], "MEDIUM"),
    (r"angular[.\-/](\d+\.\d+)",   "Angular",   "15.0",
     ["CVE-2023-26116"],              "MEDIUM"),
    (r"moment\.js",                 "Moment.js", "N/A",
     ["CVE-2022-24785", "CVE-2022-31129"], "MEDIUM"),
    (r"lodash[.\-/](\d+\.\d+)",    "Lodash",    "4.17.21",
     ["CVE-2021-23337", "CVE-2020-8203", "CVE-2019-10744"], "HIGH"),
]


def check_vulnerable_components(url: str, mode: str = "passive") -> list:
    findings = []
    r        = safe_get(url)
    req_str  = _format_request("GET", url)
    res_str  = _format_response(r)

    if not r:
        return findings

    soup       = BeautifulSoup(r.text, "html.parser")
    body_lower = r.text.lower()
    all_srcs   = [s.get("src", "") for s in soup.find_all("script", src=True)]

    # ── jQuery version ────────────────────────────────────────
    # FIX: previously `break` exited the src loop even when no vuln was found
    # (e.g. modern jQuery 3.7) — silently skipping all subsequent scripts.
    # Now: only break when a vuln finding was actually recorded.
    jquery_found = False
    for src in all_srcs + [body_lower]:
        jq = re.search(r"jquery[.\-](\d+)\.(\d+)\.?(\d*)",
                       src.lower() if isinstance(src, str) else src)
        if not jq:
            continue

        major   = int(jq.group(1))
        minor   = int(jq.group(2))
        version = f"{major}.{minor}"

        for (max_maj, max_min), (sev, cves, desc) in JQUERY_VULNS.items():
            if major < max_maj or (major == max_maj and minor <= max_min):
                src_label = src[:80] if isinstance(src, str) and src != body_lower else "inline"
                findings.append(finding(
                    check_name="A06 — Vulnerable Components",
                    title=f"Outdated jQuery {version}",
                    severity=sev,
                    owasp="A06:2021",
                    cwe="CWE-1035",
                    cvss=8.8 if sev == "CRITICAL" else 6.1,
                    detail=f"jQuery {version} detected. {desc}",
                    fix="Upgrade to latest jQuery 3.x. Run npm audit regularly.",
                    url=url,
                    confidence=88,
                    signals=[
                        f"jQuery {version} found in: {src_label}",
                        desc,
                        f"CVEs: {', '.join(cves)}",
                    ],
                    evidence_req=req_str,
                    evidence_res=res_str,
                    cve=cves,
                    mode="passive",
                ))
                jquery_found = True
                break   # Stop checking JQUERY_VULNS entries for this version

        if jquery_found:
            break   # jQuery found and vuln recorded — stop scanning srcs for jQuery

    # ── Other libraries ───────────────────────────────────────
    for pattern, lib_name, min_ver, cves, severity in LIBRARY_PATTERNS:
        match = re.search(pattern, body_lower)
        if not match:
            continue
        version = match.group(1) if match.lastindex and match.lastindex >= 1 else "unknown"

        findings.append(finding(
            check_name="A06 — Vulnerable Components",
            title=f"Potentially Vulnerable {lib_name}",
            severity=severity,
            owasp="A06:2021",
            cwe="CWE-1035",
            cvss=7.5 if severity == "HIGH" else 5.4,
            detail=f"{lib_name} (v{version}) detected."
                   + (f" Known CVEs: {', '.join(cves)}." if cves else ""),
            fix=f"Upgrade {lib_name} to {min_ver}+. Use npm audit / Snyk for continuous monitoring.",
            url=url,
            confidence=70 if version == "unknown" else 80,
            signals=[
                f"{lib_name} v{version} detected in page source",
                f"CVEs: {', '.join(cves)}" if cves else "Verify version against NVD/CVE database",
            ],
            evidence_req=req_str,
            evidence_res=res_str,
            cve=cves,
            mode="passive",
        ))

    # ── External resources without SRI ───────────────────────
    parsed_url = urlparse(url)
    no_sri     = []
    for tag in soup.find_all(["script", "link"]):
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http") and urlparse(src).netloc != parsed_url.netloc:
            if not tag.get("integrity"):
                no_sri.append(src)

    if no_sri:
        findings.append(finding(
            check_name="A06 — Vulnerable Components",
            title="External Resources Loaded Without SRI",
            severity="MEDIUM",
            owasp="A06:2021",
            cwe="CWE-829",
            cvss=6.1,
            detail=f"{len(no_sri)} external resource(s) loaded without Subresource Integrity hashes. "
                   "A compromised CDN can inject malicious code into all visitors.",
            fix="Add integrity and crossorigin attributes to all external resources. "
                "Generate hash: openssl dgst -sha384 -binary file.js | openssl base64 -A",
            url=url,
            confidence=85,
            signals=[f"{len(no_sri)} external resource(s) lack SRI"] + [s[:80] for s in no_sri[:3]],
            evidence_req=req_str,
            evidence_res=res_str,
            mode="passive",
        ))

    return findings


# ═══════════════════════════════════════════════════════════
# A07 — Identification and Authentication Failures
# ═══════════════════════════════════════════════════════════

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/wp-login.php",
    "/admin/login", "/user/login", "/account/login",
    "/api/login", "/api/auth",
]

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root",  "root"),
    ("test",  "test"),
]

SUCCESS_INDICATORS = ["dashboard", "welcome", "log out", "logout", "sign out", "profile"]
FAILURE_INDICATORS = ["invalid", "incorrect", "wrong", "failed", "error",
                       "bad credentials", "unauthorized", "try again"]


def check_authentication_failures(url: str, mode: str = "passive") -> list:
    findings  = []
    login_url = None

    for path in LOGIN_PATHS:
        r = safe_get(urljoin(url, path))
        if r and r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.find("input", {"type": "password"}):
                login_url = urljoin(url, path)
                break

    if not login_url:
        return findings

    r_login = safe_get(login_url)
    req_str = _format_request("GET", login_url)
    res_str = _format_response(r_login)

    if r_login:
        soup       = BeautifulSoup(r_login.text, "html.parser")
        csrf_input = soup.find("input", {"name": re.compile(
            r"csrf|token|nonce|_token|__requestverificationtoken", re.I)})

        if not csrf_input:
            findings.append(finding(
                check_name="A07 — Authentication Failures",
                title="Login Form May Lack CSRF Protection",
                severity="MEDIUM",
                owasp="A07:2021",
                cwe="CWE-352",
                cvss=6.5,
                detail="No CSRF token field detected in login form. CSRF against login endpoint may be possible.",
                fix="Add a cryptographically random CSRF token to all state-changing forms.",
                url=login_url,
                confidence=70,
                signals=["No CSRF token input field detected in login form"],
                evidence_req=req_str,
                evidence_res=res_str,
                mode="passive",
            ))

    # ── Default credentials (active) ──────────────────────────
    if mode == "active" and r_login:
        soup = BeautifulSoup(r_login.text, "html.parser")
        form = soup.find("form")
        if form:
            username_field = None
            password_field = None
            csrf_val       = None
            csrf_name      = None

            for inp in form.find_all("input"):
                itype = (inp.get("type") or "text").lower()
                iname = (inp.get("name") or "").lower()
                if itype == "password":
                    password_field = inp.get("name", "password")
                elif itype in ("text", "email") or any(t in iname for t in ["user", "email", "login"]):
                    username_field = inp.get("name", "username")
                if re.search(r"csrf|token", iname, re.I):
                    csrf_val  = inp.get("value")
                    csrf_name = inp.get("name")

            if username_field and password_field:
                for username, password in DEFAULT_CREDS:
                    post_data = {username_field: username, password_field: password}
                    if csrf_val and csrf_name:
                        post_data[csrf_name] = csrf_val

                    r_post = safe_post(login_url, data=post_data)
                    if r_post:
                        body_lower = r_post.text.lower()
                        success = any(s in body_lower for s in SUCCESS_INDICATORS)
                        failure = any(f in body_lower for f in FAILURE_INDICATORS)
                        if success and not failure:
                            findings.append(finding(
                                check_name="A07 — Authentication Failures",
                                title="Default Credentials Accepted",
                                severity="CRITICAL",
                                owasp="A07:2021",
                                cwe="CWE-521",
                                cvss=9.8,
                                detail=f"Login succeeded with default credentials: {username} / {password}.",
                                fix="Remove all default credentials immediately. "
                                    "Force password change on first login. "
                                    "Implement account lockout after 5 failed attempts.",
                                url=login_url,
                                confidence=90,
                                signals=[
                                    f"Credentials tested: {username} / {password}",
                                    f"HTTP {r_post.status_code}",
                                    "Success indicators in response body — no failure indicators",
                                ],
                                evidence_req=_format_request("POST", login_url,
                                                             body=urlencode(post_data)),
                                evidence_res=_format_response(r_post),
                                mode="active",
                            ))
                    time.sleep(0.3)

        # ── Rate limiting ─────────────────────────────────────
        # ── Rate limiting ─────────────────────────────────────
                blocked = False
                for i in range(6):
                    r_probe = safe_post(login_url, data={username_field: "probe_user", password_field: f"wrong{i}"})
                    if r_probe and r_probe.status_code in (429, 403):
                        blocked = True
                        break
                    time.sleep(0.1)

                if not blocked:
                    findings.append(finding(
                        check_name="A07 — Authentication Failures",
                        title="No Login Rate Limiting Detected",
                        severity="HIGH",
                        owasp="A07:2021",
                        cwe="CWE-307",
                        cvss=7.5,
                        detail="6 rapid login attempts sent with no HTTP 429 or account lockout response. "
                               "Brute-force and credential stuffing attacks are possible.",
                        fix="Rate limit to 5 attempts/15 min per IP. "
                            "Add CAPTCHA after repeated failures. Implement account lockout with notification.",
                        url=login_url,
                        confidence=75,
                        signals=[
                            "6 rapid failed logins sent",
                            "No HTTP 429 Too Many Requests received",
                            "No account lockout response observed",
                        ],
                        evidence_req=req_str,
                        evidence_res=res_str,
                        mode="active",
                    ))

    # Always surface the login endpoint as an INFO finding
    findings.append(finding(
        check_name="A07 — Authentication Failures",
        title="Login Surface Identified",
        severity="INFO",
        owasp="A07:2021",
        cwe="CWE-287",
        cvss=0.0,
        detail=f"Login form at {login_url}. Manually verify: MFA enforcement, "
               "account lockout policy, session invalidation on logout, "
               "secure password requirements.",
        fix="Enable MFA. Enforce strong password policy. "
            "Invalidate server-side sessions on logout. Log and alert on repeated failures.",
        url=login_url,
        confidence=95,
        signals=[f"Password input field found at {login_url}"],
        evidence_req=req_str,
        evidence_res=res_str,
        mode="passive",
    ))

    return findings


# ═══════════════════════════════════════════════════════════
# A09 — Security Logging and Monitoring Failures
# ═══════════════════════════════════════════════════════════

EXPOSED_FILE_PATHS = [
    ("/.git/HEAD",      "Git HEAD",          "CRITICAL", "CWE-538", 9.1),
    ("/.git/config",    "Git config",        "CRITICAL", "CWE-538", 9.1),
    ("/.svn/entries",   "SVN entries",       "CRITICAL", "CWE-538", 9.1),
    ("/.env",           "Env file",          "CRITICAL", "CWE-538", 9.1),
    ("/phpinfo.php",    "PHP info page",     "HIGH",     "CWE-200", 7.5),
    ("/info.php",       "PHP info page",     "HIGH",     "CWE-200", 7.5),
    ("/error.log",      "Error log",         "HIGH",     "CWE-532", 7.5),
    ("/access.log",     "Access log",        "HIGH",     "CWE-532", 7.5),
    ("/debug.log",      "Debug log",         "HIGH",     "CWE-532", 7.5),
    ("/logs/error.log", "Error log",         "HIGH",     "CWE-532", 7.5),
    ("/composer.json",  "Composer manifest", "MEDIUM",   "CWE-200", 5.3),
    ("/package.json",   "NPM manifest",      "MEDIUM",   "CWE-200", 5.3),
    ("/.DS_Store",      "macOS .DS_Store",   "MEDIUM",   "CWE-538", 5.3),
    ("/README.md",      "README file",       "LOW",      "CWE-200", 3.1),
    ("/CHANGELOG.md",   "Changelog",         "LOW",      "CWE-200", 3.1),
]


def check_logging_monitoring(url: str, mode: str = "passive") -> list:
    findings = []

    # ── robots.txt sensitive path disclosure ──────────────────
    r_robots = safe_get(urljoin(url, "/robots.txt"))
    if r_robots and r_robots.status_code == 200:
        disallowed    = re.findall(r"(?i)disallow:\s*(.+)", r_robots.text)
        sensitive_terms = ["admin", "config", "backup", "db", "private",
                           "secret", "api", "internal", "staging"]
        exposed = [p.strip() for p in disallowed
                   if any(t in p.lower() for t in sensitive_terms)]
        if exposed:
            findings.append(finding(
                check_name="A09 — Logging & Monitoring",
                title="Sensitive Paths in robots.txt",
                severity="LOW",
                owasp="A09:2021",
                cwe="CWE-200",
                cvss=3.1,
                detail=f"robots.txt exposes sensitive Disallow entries: {', '.join(exposed[:5])}.",
                fix="Remove sensitive paths from robots.txt — it is publicly readable "
                    "and provides no security protection.",
                url=urljoin(url, "/robots.txt"),
                confidence=90,
                signals=[
                    "robots.txt is publicly accessible",
                    f"Sensitive Disallow entries: {', '.join(exposed[:5])}",
                ],
                evidence_req=_format_request("GET", urljoin(url, "/robots.txt")),
                evidence_res=_format_response(r_robots),
                mode="passive",
            ))

    # ── Exposed sensitive files ───────────────────────────────
    for path, label, severity, cwe, cvss_score in EXPOSED_FILE_PATHS:
        r = safe_get(urljoin(url, path))
        if not r or r.status_code != 200:
            continue

        signals    = [f"HTTP 200 on {path}"]
        confidence = 50
        body_lower = r.text.lower()

        if "git" in path:
            if "ref:" in r.text or "[core]" in r.text:
                signals.append("Git file format confirmed in response body")
                confidence = 96
        elif ".env" in path:
            if any(kw in body_lower for kw in ["db_password", "secret", "api_key", "aws"]):
                signals.append("Credential/secret keywords found in .env content")
                confidence = 97
            elif "=" in r.text:
                signals.append("Key=value format consistent with .env file")
                confidence = 80
        elif ".log" in path:
            if any(t in body_lower for t in ["error", "warning", "exception", "info", "debug"]):
                signals.append("Log entry patterns detected in response")
                confidence = 85
        elif "phpinfo" in path or "info.php" in path:
            if "phpinfo()" in body_lower or "php version" in body_lower:
                signals.append("PHP info page content confirmed")
                confidence = 96
        elif path.endswith(".json"):
            if r.text.strip().startswith(("{", "[")):
                signals.append("Valid JSON manifest structure in response")
                confidence = 88
        else:
            if len(r.text) > 50:
                confidence = 65

        if confidence >= 60:
            findings.append(finding(
                check_name="A09 — Logging & Monitoring",
                title=f"Exposed {label}",
                severity=severity,
                owasp="A09:2021",
                cwe=cwe,
                cvss=cvss_score,
                detail=f"{label} is publicly accessible at {path}. "
                       "May expose credentials, source code, internal paths, or debug information.",
                fix=f"Move {path} outside the web root or block access via server config rules.",
                url=urljoin(url, path),
                confidence=min(confidence, 97),
                signals=signals,
                evidence_req=_format_request("GET", urljoin(url, path)),
                evidence_res=_format_response(r),
                mode="passive",
            ))

    return findings


# ═══════════════════════════════════════════════════════════
# A10 — Server-Side Request Forgery (SSRF)
# ═══════════════════════════════════════════════════════════

SSRF_PARAM_NAMES = {
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "link", "fetch", "load", "file", "resource",
    "callback", "return", "next", "target", "endpoint",
}

SSRF_PROBES = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
]

SSRF_RESPONSE_SIGNALS = [
    "ami-id", "instance-id", "local-ipv4",
    "computemetadata", "serviceaccounts",
    "root:", "/bin/bash",
]


def check_ssrf(url: str, mode: str = "passive") -> list:
    findings = []
    parsed   = urlparse(url)
    r        = safe_get(url)
    req_str  = _format_request("GET", url)
    res_str  = _format_response(r)

    if not r:
        return findings

    soup = BeautifulSoup(r.text, "html.parser")

    # ── Identify SSRF candidate parameters ────────────────────
    ssrf_params = []
    if parsed.query:
        for part in parsed.query.split("&"):
            if "=" in part:
                name = part.split("=")[0].lower()
                if name in SSRF_PARAM_NAMES:
                    ssrf_params.append(name)

    ssrf_form_inputs = []
    for form in soup.find_all("form"):
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            ph   = (inp.get("placeholder") or "").lower()
            if any(t in name or t in ph for t in ["url", "link", "src", "fetch", "load"]):
                ssrf_form_inputs.append(name or ph)

    if ssrf_params or ssrf_form_inputs:
        signals = []
        if ssrf_params:
            signals.append(f"URL-accepting URL parameters: {', '.join(ssrf_params)}")
        if ssrf_form_inputs:
            signals.append(f"URL-accepting form inputs: {', '.join(ssrf_form_inputs[:3])}")

        findings.append(finding(
            check_name="A10 — SSRF",
            title="SSRF Candidate Parameters Identified",
            severity="MEDIUM",
            owasp="A10:2021",
            cwe="CWE-918",
            cvss=7.5,
            detail="URL-accepting parameters detected. High-priority SSRF candidates. "
                   "Enable active mode to probe internal metadata endpoints.",
            fix="Validate and allowlist permitted URLs/domains. "
                "Block requests to RFC1918 and link-local address ranges.",
            url=url,
            confidence=70,
            signals=signals,
            evidence_req=req_str,
            evidence_res=res_str,
            mode="passive",
        ))

    # ── Active SSRF probe ─────────────────────────────────────
    if mode == "active" and ssrf_params and parsed.query:
        params   = parse_qs(parsed.query, keep_blank_values=True)
        base_url = url.split("?")[0]

        for param_name in ssrf_params:
            for probe_url in SSRF_PROBES:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = probe_url
                test_url   = base_url + "?" + urlencode(test_params)
                r_probe    = safe_get(test_url)
                req_probe  = _format_request("GET", test_url)
                res_probe  = _format_response(r_probe)

                if not r_probe:
                    continue

                body_lower = r_probe.text.lower()
                matched    = [s for s in SSRF_RESPONSE_SIGNALS if s in body_lower]
                confidence = 92 if matched else (
                    55 if r_probe.status_code == 200 and len(r_probe.text) > 100 else 0
                )

                if confidence >= 70:
                    findings.append(finding(
                        check_name="A10 — SSRF",
                        title="SSRF Confirmed",
                        severity="CRITICAL",
                        owasp="A10:2021",
                        cwe="CWE-918",
                        cvss=9.8,
                        detail=f"SSRF confirmed via parameter '{param_name}' probing '{probe_url}'. "
                               + (f"Response signals: {', '.join(matched)}" if matched
                                  else "Non-empty response from internal address."),
                        fix="Reject all user-supplied URLs resolving to internal/private ranges. "
                            "Use a strict URL allowlist. Disable URL-fetching features if not needed.",
                        url=test_url,
                        confidence=confidence,
                        signals=[
                            f"Parameter '{param_name}' probed with: {probe_url}",
                            f"HTTP {r_probe.status_code}",
                        ] + ([f"SSRF response signals: {', '.join(matched)}"] if matched else []),
                        evidence_req=req_probe,
                        evidence_res=res_probe,
                        mode="active",
                    ))

    return findings


# ═══════════════════════════════════════════════════════════
# Check registry
# ═══════════════════════════════════════════════════════════

ALL_CHECKS = [
    ("A01 — Broken Access Control",     check_broken_access_control),
    ("A02 — Cryptographic Failures",    check_cryptographic_failures),
    ("A03 — Injection",                 check_injection),
    ("A05 — Security Misconfiguration", check_security_misconfiguration),
    ("A06 — Vulnerable Components",     check_vulnerable_components),
    ("A07 — Authentication Failures",   check_authentication_failures),
    ("A09 — Logging & Monitoring",      check_logging_monitoring),
    ("A10 — SSRF",                      check_ssrf),
]