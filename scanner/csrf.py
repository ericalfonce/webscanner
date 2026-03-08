"""
MulikaScans — CSRF Detection Module
Detects forms lacking CSRF tokens and unsafe CORS configurations.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

CSRF_TOKEN_NAMES = {
    "csrf_token", "csrftoken", "_token", "authenticity_token",
    "__requestverificationtoken", "csrf", "_csrf", "xsrf_token",
    "x-csrf-token", "anti-forgery", "_xsrf",
}


def _form_has_csrf_token(form) -> bool:
    for inp in form.find_all("input", type="hidden"):
        name = str(inp.get("name") or "").lower()
        if name in CSRF_TOKEN_NAMES:
            return True
    return False


def check_csrf(url, timeout=8):
    findings = []
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}

    try:
        resp = requests.get(url, timeout=timeout, headers=headers)
        soup = BeautifulSoup(resp.text, "html.parser")

        forms = soup.find_all("form")
        for form in forms:
            method = str(form.get("method") or "get").upper()
            if method != "POST":
                continue  # CSRF primarily affects state-changing requests

            if not _form_has_csrf_token(form):
                action = str(form.get("action") or "")
                form_url = urljoin(url, action) if action else url
                findings.append({
                    "name": "Cross-Site Request Forgery (CSRF) — Missing Token",
                    "type": "CSRF",
                    "severity": "High",
                    "cvss_score": 6.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                    "category": "csrf",
                    "url_affected": form_url,
                    "parameter": "form",
                    "evidence": f"POST form at '{form_url}' lacks a recognisable CSRF token field",
                    "cwe_id": "CWE-352",
                    "owasp_category": "A01:2021",
                    "detail": "POST form missing CSRF protection token",
                    "remediation": (
                        "Implement synchroniser token pattern: generate a unique, unpredictable "
                        "CSRF token per session and validate it on every state-changing request. "
                        "Use SameSite=Strict cookies as an additional layer of defence. "
                        "Framework-level CSRF middleware (e.g. Flask-WTF, Django CSRF) is recommended."
                    ),
                    "references": [
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                        "https://cwe.mitre.org/data/definitions/352.html",
                    ],
                })

        # Check CORS misconfig
        cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        if cors_origin == "*":
            findings.append({
                "name": "Overly Permissive CORS Policy",
                "type": "CORS Misconfiguration",
                "severity": "Medium",
                "cvss_score": 5.3,
                "category": "misconfig",
                "url_affected": url,
                "parameter": "Access-Control-Allow-Origin",
                "evidence": "Access-Control-Allow-Origin: * allows any origin to make cross-origin requests",
                "cwe_id": "CWE-942",
                "owasp_category": "A05:2021",
                "detail": "Wildcard CORS origin allows any site to read response data",
                "remediation": (
                    "Restrict Access-Control-Allow-Origin to specific trusted origins. "
                    "Never use the wildcard '*' for endpoints that handle authenticated data."
                ),
                "references": [
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                ],
            })

    except requests.RequestException:
        pass

    return findings
