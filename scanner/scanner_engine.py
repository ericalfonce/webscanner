"""
MulikaScans — Scanner Engine Orchestrator
Coordinates all detection modules based on scan type and plan limits.
"""

from scanner.crawler import crawl
from scanner.headers import check_headers
from scanner.xss import test_xss
from scanner.sqli import test_sqli
from scanner.csrf import check_csrf
from scanner.ssrf import check_ssrf
from scanner.ssl_check import check_ssl
from scanner.open_redirect import check_open_redirect
from scanner.info_disclosure import check_info_disclosure


def run_scan(target_url, scan_type="quick", max_pages=10, timeout=8):
    """
    Main scan orchestrator.

    scan_type:
        quick      — headers, SSL, info_disclosure on root URL only
        full       — all checks across all crawled pages
        api        — focused on JSON endpoints, auth bypass, SSRF
        compliance — all checks + OWASP categorisation pass

    max_pages: plan-based crawl limit (free=10, basic=50, pro=200, enterprise=unlimited)
    """
    findings = []

    # ── Quick scan: root URL only ─────────────────────────────────────────────
    if scan_type == "quick":
        findings.extend(check_ssl(target_url, timeout=timeout))
        findings.extend(check_headers(target_url, timeout=timeout))
        findings.extend(check_info_disclosure(target_url, timeout=timeout))
        findings.extend(test_xss(target_url, timeout=timeout))
        findings.extend(test_sqli(target_url, timeout=timeout))
        return _dedupe(findings)

    # ── Full / Compliance / API scan: crawl + all checks ─────────────────────
    urls = crawl(target_url, max_pages=max_pages, timeout=timeout)
    if target_url not in urls:
        urls.insert(0, target_url)

    # SSL and info disclosure — once at root
    findings.extend(check_ssl(target_url, timeout=timeout))
    findings.extend(check_info_disclosure(target_url, timeout=timeout))

    for url in urls:
        findings.extend(check_headers(url, timeout=timeout))
        findings.extend(test_xss(url, timeout=timeout))
        findings.extend(test_sqli(url, timeout=timeout))
        findings.extend(check_csrf(url, timeout=timeout))

        if scan_type in ("full", "api", "compliance"):
            findings.extend(check_ssrf(url, timeout=timeout))
            findings.extend(check_open_redirect(url, timeout=timeout))

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
