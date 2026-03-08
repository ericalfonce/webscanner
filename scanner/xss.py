"""
MulikaScans — XSS Detection Module
Reflected XSS across URL parameters and form inputs.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# OWASP-aligned XSS payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "\"autofocus onfocus=alert(1) \"",
    "<details open ontoggle=alert(1)>",
]

REFLECTION_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=",
    "onerror=alert(1)",
    "<svg/onload=",
    "javascript:alert(1)",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_xss(url, timeout=8):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return findings

    for param in qs:
        for payload in XSS_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                resp = requests.get(
                    test_url, timeout=timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "MulikaScans/1.0 (Security Scanner)"}
                )
                body = resp.text
                reflected = any(ind.lower() in body.lower() for ind in REFLECTION_INDICATORS)
                if reflected:
                    findings.append({
                        "name": "Reflected Cross-Site Scripting (XSS)",
                        "type": "Reflected XSS",
                        "severity": "High",
                        "cvss_score": 7.2,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "category": "xss",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": f"Payload '{payload}' reflected unencoded in response",
                        "request_data": test_url,
                        "response_data": body[:500],
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021",
                        "detail": f"Parameter '{param}' reflects unsanitised input",
                        "remediation": (
                            "Encode all user-supplied data before rendering it in the browser. "
                            "Implement a strong Content-Security-Policy (CSP) header. "
                            "Use modern templating engines that auto-escape output."
                        ),
                        "references": [
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    })
                    break  # One confirmed finding per parameter
            except requests.RequestException:
                pass

    return findings
