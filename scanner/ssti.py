"""
Server-Side Template Injection (SSTI) Detection Module
Tests parameters for template engine injection across Jinja2, Twig,
Freemarker, Velocity, Smarty, Pebble, Mako, and Erb.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# ── Probe Payloads ────────────────────────────────────────────────────────────
# Each entry: (payload, expected_output_substring, engine_hint)
SSTI_PROBES = [
    # Math expressions — universal canary (7*7 = 49)
    ("{{7*7}}",               "49",  "Jinja2/Twig/generic"),
    ("${7*7}",                "49",  "Freemarker/Groovy"),
    ("#{7*7}",                "49",  "Pebble/Thymeleaf"),
    ("<%= 7*7 %>",            "49",  "ERB/JSP"),
    ("{{7*'7'}}",             "7777777", "Jinja2 string multiplication"),
    ("{7*7}",                 "49",  "Smarty (alt)"),
    # Engine-specific deeper probes
    ("{{config.items()}}",    "SECRET",   "Jinja2 config"),
    ("{{self.__dict__}}",     "__",       "Jinja2 object"),
    ("<#assign x=7*7>${x}",   "49",       "Freemarker"),
    ("*{7*7}",                "49",       "Spring SpEL"),
]

# If evaluation error messages appear, that also signals SSTI context
ERROR_SIGNATURES = [
    "templateerror", "template_error", "jinja2", "jinja.exceptions",
    "freemarker.core", "org.thymeleaf", "velocity.exception",
    "pebble.error", "twig\\exception", "nunjucks", "handlebars",
    "templatenotfound", "undefined variable", "unknown tag",
    "invalid template",
]


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_ssti(url: str, timeout: int = 8, quick_mode: bool = False) -> list:
    findings = []
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if not params:
        return findings

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    probes = SSTI_PROBES[:4] if quick_mode else SSTI_PROBES
    seen = set()

    for param in params:
        if param in seen:
            continue
        for payload, expected, engine_hint in probes:
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout,
                                   allow_redirects=False, verify=False)
                text = resp.text

                # Primary: evaluated output present
                if expected in text:
                    seen.add(param)
                    findings.append(_make_finding(
                        url, param, payload, expected, engine_hint,
                        test_url, text,
                        note=f"Payload '{payload}' evaluated to '{expected}'"
                    ))
                    break

                # Secondary: template error signature (confirms template context)
                text_lower = text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in text_lower:
                        seen.add(param)
                        findings.append(_make_finding(
                            url, param, payload, sig, engine_hint,
                            test_url, text,
                            severity="Medium", cvss=6.3,
                            note=f"Template error '{sig}' triggered by payload '{payload}'"
                        ))
                        break
                if param in seen:
                    break

            except Exception:
                continue

    return findings


def _make_finding(url, param, payload, evidence_value, engine_hint,
                  request_data, response_data,
                  severity="Critical", cvss=9.8, note=""):
    return {
        "name": "Server-Side Template Injection (SSTI)",
        "type": "SSTI",
        "severity": severity,
        "cvss_score": cvss,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "category": "ssti",
        "url_affected": url,
        "parameter": param,
        "evidence": note or f"Template evaluated: {evidence_value}",
        "request_data": request_data,
        "response_data": response_data[:500],
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021",
        "detail": (
            f"Parameter '{param}' is injected into a server-side template engine ({engine_hint}). "
            f"SSTI can lead to Remote Code Execution by traversing the template object graph "
            f"to reach Python/Java builtins and executing arbitrary code."
        ),
        "remediation": (
            "Never pass user input directly into template render calls. "
            "Use a sandboxed template environment. "
            "Prefer logic-less template engines (Mustache, Handlebars in escape mode). "
            "If dynamic templates are required, use a strict allowlist of safe expressions."
        ),
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/94.html",
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection",
        ],
    }
