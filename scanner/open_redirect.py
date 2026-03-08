"""
MulikaScans — Open Redirect Detection Module
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "next", "goto", "url", "target", "dest", "destination",
    "redir", "r", "to", "link", "out", "go", "continue", "forward",
}

REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "https://evil.example.com%2F@legit.com",
    "/\\evil.example.com",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_open_redirect(url, timeout=8):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}

    for param in qs:
        if param.lower() not in REDIRECT_PARAM_NAMES:
            continue

        for payload in REDIRECT_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                resp = requests.get(test_url, timeout=timeout,
                                    allow_redirects=False, headers=headers)
                location = resp.headers.get("Location", "")
                if "evil.example.com" in location:
                    findings.append({
                        "name": "Open Redirect",
                        "type": "Open Redirect",
                        "severity": "Medium",
                        "cvss_score": 6.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "category": "open_redirect",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": f"Server redirected to '{location}' using external URL in '{param}'",
                        "request_data": test_url,
                        "response_data": f"Location: {location}",
                        "cwe_id": "CWE-601",
                        "owasp_category": "A01:2021",
                        "detail": f"Parameter '{param}' allows redirection to arbitrary external URLs",
                        "remediation": (
                            "Validate all redirect destinations against a strict allow-list of "
                            "permitted URLs or paths. Reject external URLs. "
                            "Use relative paths instead of absolute URLs for redirects."
                        ),
                        "references": [
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/601.html",
                        ],
                    })
                    break  # One finding per parameter
            except requests.RequestException:
                pass

    return findings
