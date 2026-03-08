"""
MulikaScans — SQL Injection Detection Module
Error-based and time-based blind SQLi detection.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "1' OR '1'='1",
    "1 OR 1=1--",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x'='x",
    "' UNION SELECT NULL--",
]

TIME_PAYLOADS = [
    ("1' AND SLEEP(3)--", 3),
    ("1; WAITFOR DELAY '0:0:3'--", 3),
    ("1' AND pg_sleep(3)--", 3),
]

DB_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "ora-",
    "oracle error",
    "microsoft sql native client",
    "unclosed quotation mark",
    "pg_query",
    "sqlite3.operationalerror",
    "unterminated string",
    "you have an error in your sql syntax",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "unknown column",
    "odbc microsoft access",
    "syntax error converting",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_sqli(url, timeout=10):
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return findings

    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}

    for param in qs:
        found = False

        # Error-based detection
        for payload in ERROR_PAYLOADS:
            if found:
                break
            test_url = _inject_param(url, param, payload)
            try:
                resp = requests.get(test_url, timeout=timeout,
                                    allow_redirects=True, headers=headers)
                body_lower = resp.text.lower()
                for err in DB_ERRORS:
                    if err in body_lower:
                        findings.append({
                            "name": "SQL Injection (Error-Based)",
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category": "sqli",
                            "url_affected": url,
                            "parameter": param,
                            "evidence": f"Database error '{err}' triggered by payload '{payload}'",
                            "request_data": test_url,
                            "response_data": resp.text[:500],
                            "cwe_id": "CWE-89",
                            "owasp_category": "A03:2021",
                            "detail": f"Parameter '{param}' may be vulnerable to SQL Injection",
                            "remediation": (
                                "Use parameterised queries for all database operations. "
                                "Never concatenate user input into SQL strings. "
                                "Apply the principle of least privilege to database accounts."
                            ),
                            "references": [
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                        })
                        found = True
                        break
            except requests.RequestException:
                pass

        # Time-based blind detection
        if not found:
            for payload, expected_delay in TIME_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                try:
                    t_start = time.time()
                    requests.get(test_url, timeout=timeout + expected_delay + 2,
                                 allow_redirects=True, headers=headers)
                    elapsed = time.time() - t_start
                    if elapsed >= expected_delay * 0.9:
                        findings.append({
                            "name": "SQL Injection (Time-Based Blind)",
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category": "sqli",
                            "url_affected": url,
                            "parameter": param,
                            "evidence": f"Response delayed {elapsed:.1f}s with time-based payload",
                            "request_data": test_url,
                            "response_data": "",
                            "cwe_id": "CWE-89",
                            "owasp_category": "A03:2021",
                            "detail": f"Parameter '{param}' shows time-based blind SQLi behaviour",
                            "remediation": (
                                "Use parameterised queries for all database operations. "
                                "Validate and whitelist all user inputs."
                            ),
                            "references": [
                                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                            ],
                        })
                        found = True
                        break
                except requests.RequestException:
                    pass

    return findings
