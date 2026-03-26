"""
CORS Misconfiguration Detection Module
Tests for insecure Cross-Origin Resource Sharing policies that allow
attackers to make authenticated cross-origin requests.
"""

import requests


ORIGIN_PROBES = [
    ("https://evil.example.com",      "reflected_evil"),
    ("null",                          "null_origin"),
    ("https://mulikascans.com.evil.example.com", "subdomain_bypass"),
]


def check_cors(url: str, timeout: int = 8, session=None) -> list:
    _req = session if session is not None else requests
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    for origin, probe_type in ORIGIN_PROBES:
        try:
            resp = session.get(
                url, timeout=timeout, verify=False,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                }
            )
        except Exception:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")

        # ── Wildcard ACAO ──────────────────────────────────────────────────────
        if acao == "*":
            findings.append({
                "name": "CORS Wildcard Origin",
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "category": "cors",
                "url_affected": url,
                "parameter": "Origin header",
                "evidence": f"Access-Control-Allow-Origin: * — any origin can read responses",
                "request_data": f"GET {url} Origin: {origin}",
                "response_data": f"ACAO: {acao}  ACAC: {acac}",
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021",
                "detail": (
                    "The server returns Access-Control-Allow-Origin: * allowing any website "
                    "to read responses. Combined with credentials this is critical."
                ),
                "remediation": (
                    "Replace the wildcard with an explicit allowlist of trusted origins. "
                    "Never combine wildcard with Access-Control-Allow-Credentials: true."
                ),
                "references": [
                    "https://portswigger.net/web-security/cors",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
            })
            break  # Only report once for this URL

        # ── Reflected arbitrary origin + credentials ───────────────────────────
        if acao == origin and acac == "true":
            findings.append({
                "name": "CORS: Reflected Origin with Credentials — Critical",
                "type": "CORS Misconfiguration",
                "severity": "Critical",
                "cvss_score": 9.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
                "category": "cors",
                "url_affected": url,
                "parameter": "Origin header",
                "evidence": (
                    f"Server reflected Origin '{origin}' in ACAO and also set "
                    f"Access-Control-Allow-Credentials: true — attackers can make "
                    f"authenticated cross-origin requests from any domain"
                ),
                "request_data": f"GET {url} Origin: {origin}",
                "response_data": f"ACAO: {acao}  ACAC: {acac}  ACAM: {acam}",
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021",
                "detail": (
                    "The server reflects the attacker-controlled Origin header and also "
                    "allows credentials. This is the most dangerous CORS misconfiguration — "
                    "it allows any website to make authenticated requests to this API and "
                    "read the responses, bypassing SameSite cookie protections."
                ),
                "remediation": (
                    "Maintain a strict server-side allowlist of trusted origins. "
                    "Validate the Origin header against this list before reflecting it. "
                    "Never reflect arbitrary origins when Allow-Credentials is true."
                ),
                "references": [
                    "https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack",
                    "https://cwe.mitre.org/data/definitions/942.html",
                ],
            })
            break

        # ── Reflected arbitrary origin without credentials ─────────────────────
        if acao == origin and acac != "true":
            findings.append({
                "name": "CORS: Arbitrary Origin Reflected",
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "cvss_score": 5.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                "category": "cors",
                "url_affected": url,
                "parameter": "Origin header",
                "evidence": f"Server reflected Origin '{origin}' in ACAO (no credentials)",
                "request_data": f"GET {url} Origin: {origin}",
                "response_data": f"ACAO: {acao}  ACAC: {acac}",
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021",
                "detail": (
                    "The server reflects attacker-controlled origins. Without credentials "
                    "the impact is limited to public endpoints, but can still leak data."
                ),
                "remediation": (
                    "Implement a strict origin allowlist and validate against it "
                    "before echoing the Origin header."
                ),
                "references": [
                    "https://portswigger.net/web-security/cors",
                ],
            })
            break

        # ── Null origin accepted ───────────────────────────────────────────────
        if probe_type == "null_origin" and acao == "null":
            findings.append({
                "name": "CORS: Null Origin Accepted",
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "cvss_score": 6.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "category": "cors",
                "url_affected": url,
                "parameter": "Origin header",
                "evidence": "Server accepts Origin: null — exploitable from sandboxed iframes",
                "request_data": f"GET {url} Origin: null",
                "response_data": f"ACAO: {acao}  ACAC: {acac}",
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021",
                "detail": (
                    "The server accepts Origin: null. Sandboxed iframes, local files, and "
                    "redirected cross-origin requests all send a null origin, allowing "
                    "attackers to craft pages that make credentialed requests."
                ),
                "remediation": "Never add 'null' to the CORS origin allowlist.",
                "references": [
                    "https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack",
                ],
            })

    return findings
