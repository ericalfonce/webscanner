"""
MulikaScans — SSRF Detection Module
Detects parameters likely to trigger Server-Side Request Forgery.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Parameter names commonly used for URL/resource fetching
SSRF_PARAM_NAMES = {
    "url", "uri", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "callback", "return", "returnurl",
    "path", "file", "fetch", "load", "link", "img", "image",
    "proxy", "endpoint", "host", "server", "site", "page", "ref",
    "data", "feed", "service", "resource", "download",
}

# Internal network SSRF canaries to try injecting
SSRF_CANARIES = [
    "http://169.254.169.254/latest/meta-data/",    # AWS metadata
    "http://metadata.google.internal/",             # GCP metadata
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
]

# Indicators in response that suggest successful SSRF
SSRF_INDICATORS = [
    "ami-id",            # AWS metadata
    "instance-id",
    "computeMetadata",   # GCP
    "root:x:0:",         # /etc/passwd
    "127.0.0.1",
    "localhost",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def check_ssrf(url, timeout=8):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}

    for param in qs:
        if param.lower() not in SSRF_PARAM_NAMES:
            continue  # Only test likely SSRF parameters

        for canary in SSRF_CANARIES:
            test_url = _inject_param(url, param, canary)
            try:
                resp = requests.get(test_url, timeout=timeout,
                                    allow_redirects=True, headers=headers)
                body = resp.text
                for indicator in SSRF_INDICATORS:
                    if indicator.lower() in body.lower():
                        findings.append({
                            "name": "Server-Side Request Forgery (SSRF)",
                            "type": "SSRF",
                            "severity": "Critical",
                            "cvss_score": 9.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                            "category": "ssrf",
                            "url_affected": url,
                            "parameter": param,
                            "evidence": (
                                f"Indicator '{indicator}' found in response after injecting "
                                f"internal URL '{canary}' into parameter '{param}'"
                            ),
                            "request_data": test_url,
                            "response_data": body[:500],
                            "cwe_id": "CWE-918",
                            "owasp_category": "A10:2021",
                            "detail": f"Parameter '{param}' may allow fetching of internal resources",
                            "remediation": (
                                "Validate and whitelist all URLs supplied by users. "
                                "Reject requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x). "
                                "Use an allow-list of permitted domains/schemes. "
                                "Disable unnecessary URL-fetching features. "
                                "Block cloud provider metadata endpoints at the network layer."
                            ),
                            "references": [
                                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/918.html",
                            ],
                        })
                        return findings  # One confirmed SSRF is sufficient
            except requests.RequestException:
                pass

    return findings
