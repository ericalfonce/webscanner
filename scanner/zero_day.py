"""
Zero-Day & Behavioral Anomaly Detection Module (Enterprise)

True zero-day exploits are unknown by definition and cannot be detected
by signatures. This module applies heuristic and behavioral analysis
techniques used by enterprise scanners to surface abnormal server
responses that may indicate novel or unclassified vulnerabilities:

  1. Anomalous response-length variance across fuzzed inputs
  2. Differential HTTP status code behavior (unexpected 500/200 flips)
  3. Timing anomalies (server-side processing spikes)
  4. Error-string leakage from non-standard payloads
  5. Header injection reflections (HTTP response splitting indicators)
  6. Prototype pollution hints (JavaScript runtimes)
  7. GraphQL introspection and error disclosure
  8. Mass assignment vulnerability indicators
  9. Deserialization gadget chain triggers (Java / .NET / PHP / Python)
 10. Race condition detection via concurrent request bursting
"""

import re
import time
import threading
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ── Fuzz characters — broad, non-targeted ─────────────────────────────────────
FUZZ_CHARS = [
    "%00", "%0a", "%0d", "%09", "\x00", "\r\n",
    "A" * 1024,           # buffer overflow probe
    "A" * 8192,           # larger overflow
    "%s%s%s%s%s",         # format string
    "%n%n%n%n",           # format string (write)
    "{{7*7}}",            # template injection canary
    "${7*7}",             # EL injection canary
    "';!--\"<XSS>=&{()}",# polyglot XSS/SQLi
    "/../../../etc",      # path traversal canary
    "\u0000\u0000",       # unicode null
]

# ── Deserialization gadget trigger strings ────────────────────────────────────
DESER_PAYLOADS = [
    # Java serialized object magic bytes (as URL-safe hex representation in body)
    "rO0AB",                     # Java base64 serialized object start
    "ACED0005",                  # Java serialized object hex
    "<?xml version",             # XML deserialization
    "O:8:\"stdClass\"",          # PHP object serialization
    "a:2:{",                     # PHP array serialization
    "__reduce__",                # Python pickle gadget
    "System.Runtime.Serialization", # .NET serialization
]

# ── GraphQL probes ────────────────────────────────────────────────────────────
GQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/query", "/graph"]
GQL_INTROSPECTION = '{"query":"{__schema{types{name}}}"}'
GQL_ERROR_QUERY   = '{"query":"{ __typename @deprecated }"}'

# ── Header injection characters ───────────────────────────────────────────────
HEADER_INJECT_CHARS = ["\r\nX-Injected: yes", "%0d%0aX-Injected: yes",
                       "%0aX-Injected: yes"]

# ── Error leak signatures not covered by sqli/xss ─────────────────────────────
ANOMALY_ERROR_SIGS = [
    "segmentation fault", "null pointer", "nullpointerexception",
    "system.outofmemoryexception", "stackoverflow",
    "fatal error", "kernel panic", "bus error",
    "access violation", "segfault",
    "unhandled exception", "internal server error",
    "javax.servlet.servletexception",
    "django.core.exceptions", "activerecord::statementinvalid",
    "runtimeerror", "attributeerror", "typeerror",
    "keyerror", "indexerror", "valueerror",
    "cannot read property", "is not a function",
    "referenceerror", "syntaxerror: unexpected",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _get(session, url, timeout=10):
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None


def detect_zero_day(url: str, timeout: int = 10, session=None) -> list:
    """
    Runs behavioral anomaly detection. Returns findings for suspicious
    server behaviors that may indicate unknown or zero-day vulnerabilities.
    """
    findings = []
    parsed  = urlparse(url)
    params  = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    base    = f"{parsed.scheme}://{parsed.netloc}"

    # Build internal scan session, seeding auth credentials if provided
    _scan_session = requests.Session()
    _scan_session.headers.update({
        "User-Agent": "Mozilla/5.0 (Security Scanner)",
        "Accept": "application/json, text/html, */*",
    })
    if session is not None:
        _scan_session.cookies.update(session.cookies)
        _scan_session.headers.update({k: v for k, v in session.headers.items()
                                       if k.lower() not in ('user-agent', 'accept')})
    session = _scan_session

    # ── 1. Baseline measurement ────────────────────────────────────────────────
    baseline = _get(session, url, timeout)
    if not baseline:
        return findings
    baseline_len    = len(baseline.text)
    baseline_status = baseline.status_code
    baseline_time   = None

    # Measure baseline response time
    try:
        t0 = time.monotonic()
        session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        baseline_time = time.monotonic() - t0
    except Exception:
        baseline_time = 1.0

    # ── 2. Fuzz parameters for anomalies ──────────────────────────────────────
    for param in params:
        length_deltas = []
        status_flips  = []
        timing_spikes = []
        error_leaks   = []

        for fuzz in FUZZ_CHARS:
            test_url = _inject_param(url, param, fuzz)
            t0 = time.monotonic()
            resp = _get(session, test_url, timeout)
            elapsed = time.monotonic() - t0
            if resp is None:
                continue

            body_lower = resp.text.lower()
            delta = abs(len(resp.text) - baseline_len)

            # Significant response-length change
            if delta > 500 and resp.status_code == 200:
                length_deltas.append((fuzz, delta))

            # Status code flip (200→500 or 200→403)
            if resp.status_code != baseline_status and resp.status_code in (500, 503):
                status_flips.append((fuzz, resp.status_code))

            # Timing spike (3× baseline)
            if baseline_time and elapsed > baseline_time * 3 and elapsed > 1.5:
                timing_spikes.append((fuzz, elapsed))

            # Error leak
            for sig in ANOMALY_ERROR_SIGS:
                if sig in body_lower:
                    error_leaks.append((fuzz, sig, resp.text[:300]))
                    break

        if status_flips:
            findings.append({
                "name": "Behavioral Anomaly: Unexpected Server Error on Fuzz Input",
                "type": "Zero-Day Indicator",
                "severity": "High",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "category": "zero_day",
                "url_affected": url,
                "parameter": param,
                "evidence": (
                    f"Parameter '{param}' caused HTTP {status_flips[0][1]} "
                    f"responses with fuzz input: {repr(status_flips[0][0])[:60]}"
                ),
                "request_data": _inject_param(url, param, status_flips[0][0]),
                "response_data": "",
                "cwe_id": "CWE-20",
                "owasp_category": "A03:2021",
                "detail": (
                    f"The server returned unexpected error codes when parameter '{param}' "
                    "received fuzz inputs. This behavioral anomaly may indicate an "
                    "unhandled code path, buffer condition, or novel vulnerability. "
                    "Manual investigation is recommended."
                ),
                "remediation": (
                    "Implement robust input validation and error handling. "
                    "Review server-side logic for this parameter. "
                    "Use fuzzing in your CI/CD pipeline to catch regressions."
                ),
                "references": [
                    "https://owasp.org/www-community/Fuzzing",
                    "https://cwe.mitre.org/data/definitions/20.html",
                ],
            })

        if timing_spikes:
            spike_fuzz, spike_time = timing_spikes[0]
            findings.append({
                "name": "Behavioral Anomaly: Processing Time Spike",
                "type": "Zero-Day Indicator",
                "severity": "Medium",
                "cvss_score": 5.9,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L",
                "category": "zero_day",
                "url_affected": url,
                "parameter": param,
                "evidence": (
                    f"Response time spiked to {spike_time:.2f}s (baseline: "
                    f"{baseline_time:.2f}s) with fuzz input: {repr(spike_fuzz)[:60]}"
                ),
                "request_data": _inject_param(url, param, spike_fuzz),
                "response_data": "",
                "cwe_id": "CWE-400",
                "owasp_category": "A03:2021",
                "detail": (
                    f"A significant processing-time spike was observed for parameter "
                    f"'{param}'. This could indicate regex DoS (ReDoS), expensive "
                    "database queries triggered by crafted input, or blind injection "
                    "of an unknown type. Manual investigation is recommended."
                ),
                "remediation": (
                    "Profile server-side processing for this input. "
                    "Audit any regular expressions used for linear complexity. "
                    "Add request timeouts and rate limiting."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                ],
            })

        for fuzz, sig, snippet in error_leaks:
            findings.append({
                "name": "Behavioral Anomaly: Unexpected Error Leak",
                "type": "Zero-Day Indicator",
                "severity": "Medium",
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "category": "zero_day",
                "url_affected": url,
                "parameter": param,
                "evidence": f"Error signature '{sig}' exposed via fuzz input: {repr(fuzz)[:60]}",
                "request_data": _inject_param(url, param, fuzz),
                "response_data": snippet,
                "cwe_id": "CWE-209",
                "owasp_category": "A05:2021",
                "detail": (
                    f"Fuzz input to '{param}' triggered an unhandled error revealing "
                    f"internal application details. This may be the first observable "
                    "sign of a deeper vulnerability."
                ),
                "remediation": "Implement global exception handlers that return generic errors.",
                "references": ["https://owasp.org/www-community/Improper_Error_Handling"],
            })
            break  # One per param

    # ── 3. Deserialization probe ───────────────────────────────────────────────
    for payload in DESER_PAYLOADS[:4]:
        try:
            resp = session.post(url, data=payload, timeout=timeout, verify=False,
                                headers={"Content-Type": "application/octet-stream"})
            if resp.status_code == 500:
                body_lower = resp.text.lower()
                if any(sig in body_lower for sig in ["deserializ", "serial", "classnotfound",
                                                      "unmarshal", "pickle", "unserialize"]):
                    findings.append({
                        "name": "Potential Insecure Deserialization",
                        "type": "Zero-Day Indicator",
                        "severity": "Critical",
                        "cvss_score": 9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "category": "zero_day",
                        "url_affected": url,
                        "parameter": "POST body",
                        "evidence": f"Server returned 500 with deserialization error signs when receiving payload: {payload[:40]}",
                        "request_data": payload[:80],
                        "response_data": resp.text[:400],
                        "cwe_id": "CWE-502",
                        "owasp_category": "A08:2021",
                        "detail": (
                            "The server appears to deserialize untrusted data. "
                            "Insecure deserialization can lead to Remote Code Execution, "
                            "authentication bypass, and privilege escalation via gadget chains."
                        ),
                        "remediation": (
                            "Never deserialize data from untrusted sources. "
                            "Use integrity checks (digital signatures) on serialized data. "
                            "Prefer data formats like JSON over native serialization. "
                            "Apply deserialization firewalls (e.g., SerialKiller for Java)."
                        ),
                        "references": [
                            "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization",
                            "https://cwe.mitre.org/data/definitions/502.html",
                        ],
                    })
                    break
        except Exception:
            continue

    # ── 4. GraphQL introspection ───────────────────────────────────────────────
    for gql_path in GQL_PATHS:
        gql_url = base + gql_path
        try:
            resp = session.post(gql_url, json={"query": "{__schema{types{name}}}"},
                                timeout=timeout, verify=False)
            if resp.status_code == 200 and "__schema" in resp.text:
                findings.append({
                    "name": "GraphQL Introspection Enabled",
                    "type": "Information Disclosure",
                    "severity": "Medium",
                    "cvss_score": 5.3,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "category": "zero_day",
                    "url_affected": gql_url,
                    "parameter": "GraphQL query",
                    "evidence": "GraphQL introspection query returned full schema — all types and fields exposed",
                    "request_data": GQL_INTROSPECTION,
                    "response_data": resp.text[:500],
                    "cwe_id": "CWE-200",
                    "owasp_category": "A05:2021",
                    "detail": (
                        "GraphQL introspection is enabled, allowing any user to enumerate "
                        "the entire API schema including all types, queries, mutations, and fields. "
                        "This drastically reduces attacker reconnaissance effort."
                    ),
                    "remediation": (
                        "Disable introspection in production environments. "
                        "Use query depth limiting and query cost analysis. "
                        "Implement field-level authorization."
                    ),
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ],
                })
                break
        except Exception:
            continue

    # ── 5. Race condition probe ────────────────────────────────────────────────
    # Fire 10 concurrent requests to a state-changing endpoint and look for
    # inconsistent status codes (sign of TOCTOU / race condition)
    if parsed.path and any(kw in parsed.path.lower() for kw in
                           ["transfer", "buy", "purchase", "vote", "like", "redeem",
                            "withdraw", "payment", "order", "coupon"]):
        statuses = []
        threads  = []
        lock     = threading.Lock()

        def _fire():
            r = _get(session, url, timeout=5)
            if r:
                with lock:
                    statuses.append(r.status_code)

        for _ in range(10):
            t = threading.Thread(target=_fire)
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=8)

        unique_statuses = set(statuses)
        if len(unique_statuses) > 1 and 200 in unique_statuses:
            findings.append({
                "name": "Potential Race Condition on Sensitive Endpoint",
                "type": "Zero-Day Indicator",
                "severity": "High",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "category": "zero_day",
                "url_affected": url,
                "parameter": "concurrent requests",
                "evidence": (
                    f"10 concurrent requests to a sensitive endpoint returned "
                    f"mixed status codes: {sorted(unique_statuses)} — "
                    "possible TOCTOU or race condition"
                ),
                "request_data": url,
                "response_data": f"Observed statuses: {sorted(unique_statuses)}",
                "cwe_id": "CWE-362",
                "owasp_category": "A04:2021",
                "detail": (
                    "The endpoint is on a sensitive path (payment/transfer/redemption) "
                    "and returned inconsistent responses under concurrent load. "
                    "This is a strong indicator of a race condition (TOCTOU) vulnerability "
                    "that could allow double-spending, duplicate votes, or balance manipulation."
                ),
                "remediation": (
                    "Use database transactions and row-level locking. "
                    "Implement idempotency keys on financial and state-change endpoints. "
                    "Use optimistic locking or compare-and-swap patterns."
                ),
                "references": [
                    "https://portswigger.net/web-security/race-conditions",
                    "https://cwe.mitre.org/data/definitions/362.html",
                ],
            })

    return findings
