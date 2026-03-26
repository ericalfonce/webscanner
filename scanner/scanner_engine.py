"""
MulikaScans — Scanner Engine Orchestrator
Coordinates all detection modules based on scan type and plan limits.

Scan types:
  quick      — fast surface scan: SSL, headers, info disclosure, basic XSS/SQLi
  full       — deep scan: all checks across all crawled pages
  api        — API-focused: SSRF, CORS, JWT, auth bypass across crawled pages
  compliance — everything including SSTI, command injection, path traversal
  enterprise — compliance + zero-day behavioral analysis + tech fingerprinting
"""

import requests as _requests_module

from scanner.crawler import crawl
from scanner.headers import check_headers
from scanner.xss import test_xss
from scanner.sqli import test_sqli
from scanner.csrf import check_csrf
from scanner.ssrf import check_ssrf
from scanner.ssl_check import check_ssl
from scanner.open_redirect import check_open_redirect
from scanner.info_disclosure import check_info_disclosure
from scanner.command_injection import test_command_injection
from scanner.path_traversal import test_path_traversal
from scanner.ssti import test_ssti
from scanner.cors import check_cors
from scanner.jwt_scan import check_jwt
from scanner.tech_detect import fingerprint
from scanner.zero_day import detect_zero_day
from scanner.xxe import check_xxe


def _make_session(auth_cookies=None, auth_headers=None):
    """
    Build a requests.Session with caller-supplied auth credentials.
    Returns None if no credentials provided (modules fall back to plain requests).
    """
    if not auth_cookies and not auth_headers:
        return None
    s = _requests_module.Session()
    s.headers.update({"User-Agent": "MulikaScans/1.0 (Security Scanner)"})
    if auth_headers:
        s.headers.update(auth_headers)
    if auth_cookies:
        s.cookies.update(auth_cookies)
    return s


def run_scan(target_url, scan_type="quick", max_pages=10, timeout=8,
             auth_cookies=None, auth_headers=None):
    """
    Main scan orchestrator.

    scan_type:
        quick      — root URL: SSL, headers, info disclosure, XSS(quick), SQLi(quick)
        full       — all pages: headers, XSS, SQLi, CSRF, SSRF, open redirect,
                     CORS, command injection, path traversal, JWT, tech fingerprint, XXE
        api        — full + JWT focus, CORS, SSRF on all pages
        compliance — everything in full + SSTI, command injection, deserialization, XXE
        enterprise — compliance + zero-day behavioral analysis on all pages

    max_pages: free=10, basic=50, pro=200, enterprise=unlimited
    auth_cookies: dict of cookie name→value for authenticated scanning
    auth_headers: dict of header name→value (e.g. {"Authorization": "Bearer ..."})
    """
    findings = []
    session = _make_session(auth_cookies=auth_cookies, auth_headers=auth_headers)

    # ── Quick scan: root URL only, speed-capped ───────────────────────────────
    if scan_type == "quick":
        qt = min(timeout, 5)
        findings.extend(check_ssl(target_url, timeout=qt))
        findings.extend(check_headers(target_url, timeout=qt, session=session))
        findings.extend(check_info_disclosure(target_url, timeout=qt, session=session))
        findings.extend(fingerprint(target_url, timeout=qt, session=session))
        findings.extend(test_xss(target_url, timeout=qt, quick_mode=True, session=session))
        findings.extend(test_sqli(target_url, timeout=qt, quick_mode=True, session=session))
        findings.extend(check_cors(target_url, timeout=qt, session=session))
        findings.extend(check_jwt(target_url, timeout=qt, session=session))
        return _dedupe(findings)

    # ── Crawl phase (all non-quick scan types) ────────────────────────────────
    urls = crawl(target_url, max_pages=max_pages, timeout=timeout, session=session)
    if target_url not in urls:
        urls.insert(0, target_url)

    # Once-per-scan checks (root URL only)
    findings.extend(check_ssl(target_url, timeout=timeout))
    findings.extend(check_info_disclosure(target_url, timeout=timeout, session=session))
    findings.extend(fingerprint(target_url, timeout=timeout, session=session))
    findings.extend(check_jwt(target_url, timeout=timeout, session=session))

    # XXE — tested once on root URL for full/api/compliance/enterprise
    if scan_type in ("full", "api", "compliance", "enterprise"):
        findings.extend(check_xxe(target_url, timeout=timeout, session=session))

    # ── Per-URL checks ────────────────────────────────────────────────────────
    for url in urls:
        findings.extend(check_headers(url, timeout=timeout, session=session))
        findings.extend(test_xss(url, timeout=timeout, session=session))
        findings.extend(test_sqli(url, timeout=timeout, session=session))
        findings.extend(check_csrf(url, timeout=timeout, session=session))
        findings.extend(check_ssrf(url, timeout=timeout, session=session))
        findings.extend(check_open_redirect(url, timeout=timeout, session=session))
        findings.extend(check_cors(url, timeout=timeout, session=session))

        # Full / API / Compliance / Enterprise
        if scan_type in ("full", "api", "compliance", "enterprise"):
            findings.extend(test_command_injection(url, timeout=timeout, session=session))
            findings.extend(test_path_traversal(url, timeout=timeout, session=session))

        # Compliance / Enterprise — deeper analysis
        if scan_type in ("compliance", "enterprise"):
            findings.extend(test_ssti(url, timeout=timeout, session=session))

        # Enterprise — behavioral zero-day analysis
        if scan_type == "enterprise":
            findings.extend(detect_zero_day(url, timeout=timeout, session=session))

    return _dedupe(findings)


def _dedupe(findings):
    """Remove duplicate findings by (name, url_affected, parameter) key."""
    seen = set()
    unique = []
    for f in findings:
        key = (
            f.get("name", ""),
            f.get("url_affected", ""),
            f.get("parameter", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts
