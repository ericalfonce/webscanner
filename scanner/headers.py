"""
MulikaScans — Security Headers Checker
Checks for missing/misconfigured HTTP security headers.
"""

import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "cvss_score": 6.1,
        "cwe_id": "CWE-1021",
        "owasp_category": "A05:2021",
        "remediation": (
            "Implement a Content-Security-Policy header to restrict the sources of "
            "scripts, styles, images, and other resources. Start with a restrictive policy "
            "and gradually loosen it. Example: Content-Security-Policy: default-src 'self'"
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ],
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "cvss_score": 4.7,
        "cwe_id": "CWE-1021",
        "owasp_category": "A05:2021",
        "remediation": (
            "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks. "
            "Alternatively, use Content-Security-Policy: frame-ancestors 'none'."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "https://owasp.org/www-community/attacks/Clickjacking",
        ],
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "cvss_score": 3.1,
        "cwe_id": "CWE-16",
        "owasp_category": "A05:2021",
        "remediation": "Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing attacks.",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ],
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "cvss_score": 6.5,
        "cwe_id": "CWE-319",
        "owasp_category": "A02:2021",
        "remediation": (
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload "
            "to enforce HTTPS connections and prevent protocol downgrade attacks."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://hstspreload.org/",
        ],
    },
    "Referrer-Policy": {
        "severity": "Low",
        "cvss_score": 2.4,
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021",
        "remediation": (
            "Add Referrer-Policy: strict-origin-when-cross-origin to control what information "
            "is sent in the Referer header when navigating away from your site."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        ],
    },
    "Permissions-Policy": {
        "severity": "Low",
        "cvss_score": 2.4,
        "cwe_id": "CWE-16",
        "owasp_category": "A05:2021",
        "remediation": (
            "Add Permissions-Policy to disable browser features not needed by your application. "
            "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        ],
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "Info",
        "cvss_score": 0.0,
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021",
        "detail_template": "Server header discloses version information: {}",
        "remediation": "Remove or obfuscate the Server header to avoid revealing technology stack.",
        "references": [],
    },
    "X-Powered-By": {
        "severity": "Info",
        "cvss_score": 0.0,
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021",
        "detail_template": "X-Powered-By header discloses technology: {}",
        "remediation": "Remove the X-Powered-By header to avoid revealing the application framework.",
        "references": [],
    },
}


def check_headers(url, timeout=8, session=None):
    _req = session if session is not None else requests
    findings = []
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}

    try:
        resp = _req.get(url, timeout=timeout, allow_redirects=True, headers=headers)
        resp_headers = resp.headers

        # Check missing security headers
        for header_name, cfg in SECURITY_HEADERS.items():
            if header_name not in resp_headers:
                findings.append({
                    "name": f"Missing Security Header: {header_name}",
                    "type": "Missing Security Header",
                    "severity": cfg["severity"],
                    "cvss_score": cfg["cvss_score"],
                    "category": "headers",
                    "url_affected": url,
                    "parameter": header_name,
                    "evidence": f"HTTP response does not include the '{header_name}' header",
                    "cwe_id": cfg["cwe_id"],
                    "owasp_category": cfg["owasp_category"],
                    "detail": f"{header_name} is missing",
                    "remediation": cfg["remediation"],
                    "references": cfg["references"],
                })

        # Check for dangerous/verbose headers
        for header_name, cfg in DANGEROUS_HEADERS.items():
            val = resp_headers.get(header_name)
            if val:
                findings.append({
                    "name": f"Information Disclosure: {header_name} Header",
                    "type": "Information Disclosure",
                    "severity": cfg["severity"],
                    "cvss_score": cfg["cvss_score"],
                    "category": "info_disclosure",
                    "url_affected": url,
                    "parameter": header_name,
                    "evidence": cfg["detail_template"].format(val),
                    "cwe_id": cfg["cwe_id"],
                    "owasp_category": cfg["owasp_category"],
                    "detail": cfg["detail_template"].format(val),
                    "remediation": cfg["remediation"],
                    "references": cfg["references"],
                })

        # Check for insecure cookie flags
        set_cookie = resp_headers.get("Set-Cookie", "")
        if set_cookie:
            issues = []
            if "httponly" not in set_cookie.lower():
                issues.append("HttpOnly flag missing")
            if "secure" not in set_cookie.lower():
                issues.append("Secure flag missing")
            if "samesite" not in set_cookie.lower():
                issues.append("SameSite attribute missing")
            if issues:
                findings.append({
                    "name": "Insecure Cookie Configuration",
                    "type": "Insecure Cookie",
                    "severity": "Medium",
                    "cvss_score": 5.4,
                    "category": "misconfig",
                    "url_affected": url,
                    "parameter": "Set-Cookie",
                    "evidence": f"Cookie flags missing: {', '.join(issues)}",
                    "cwe_id": "CWE-614",
                    "owasp_category": "A02:2021",
                    "detail": f"Cookie configuration issues: {', '.join(issues)}",
                    "remediation": (
                        "Set HttpOnly, Secure, and SameSite=Strict (or Lax) flags on all cookies. "
                        "HttpOnly prevents JavaScript access; Secure ensures HTTPS-only transmission."
                    ),
                    "references": [
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                })

    except requests.RequestException:
        pass

    return findings
