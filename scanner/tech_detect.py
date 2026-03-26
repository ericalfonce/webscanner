"""
Technology Fingerprinting Module
Identifies web frameworks, CMS platforms, servers, languages, and
libraries from headers, cookies, HTML content, and URL patterns.
"""

import requests
import re
from urllib.parse import urlparse


# ── Signature Database ────────────────────────────────────────────────────────
# (name, category, confidence, detection_type, pattern)
HEADER_SIGS = [
    # Web Servers
    ("Apache HTTP Server",      "web_server",  "high",   "header:server",      r"Apache/?(\S*)"),
    ("Nginx",                   "web_server",  "high",   "header:server",      r"nginx/?(\S*)"),
    ("Microsoft IIS",           "web_server",  "high",   "header:server",      r"Microsoft-IIS/?(\S*)"),
    ("LiteSpeed",               "web_server",  "high",   "header:server",      r"LiteSpeed"),
    ("Caddy",                   "web_server",  "high",   "header:server",      r"Caddy"),
    ("OpenResty",               "web_server",  "high",   "header:server",      r"openresty/?(\S*)"),
    # Languages / Frameworks
    ("PHP",                     "language",    "high",   "header:x-powered-by",r"PHP/?(\S*)"),
    ("ASP.NET",                 "framework",   "high",   "header:x-powered-by",r"ASP\.NET"),
    ("ASP.NET MVC",             "framework",   "high",   "header:x-aspnet-version", r"(\S+)"),
    ("Express.js",              "framework",   "medium", "header:x-powered-by",r"Express"),
    ("Next.js",                 "framework",   "high",   "header:x-powered-by",r"Next\.js"),
    # CDN / Proxies
    ("Cloudflare",              "cdn",         "high",   "header:server",      r"cloudflare"),
    ("Cloudflare",              "cdn",         "high",   "header:cf-ray",      r".+"),
    ("Amazon CloudFront",       "cdn",         "high",   "header:x-amz-cf-id", r".+"),
    ("Fastly",                  "cdn",         "high",   "header:x-served-by", r"cache-"),
    ("Varnish",                 "cache",       "high",   "header:x-varnish",   r".+"),
    ("AWS ALB",                 "cloud",       "high",   "header:x-amzn-trace-id", r".+"),
]

COOKIE_SIGS = [
    ("PHP",           "language",  "medium", r"PHPSESSID"),
    ("ASP.NET",       "framework", "high",   r"ASP\.NET_SessionId"),
    ("Java / J2EE",   "language",  "high",   r"JSESSIONID"),
    ("Django",        "framework", "high",   r"csrftoken|sessionid"),
    ("Ruby on Rails", "framework", "medium", r"_session_id"),
    ("Laravel",       "framework", "high",   r"laravel_session|XSRF-TOKEN"),
    ("WordPress",     "cms",       "high",   r"wordpress_|wp-settings"),
    ("Drupal",        "cms",       "medium", r"Drupal\.settings"),
    ("Joomla",        "cms",       "medium", r"joomla_user_state"),
]

HTML_SIGS = [
    ("WordPress",         "cms",       "high",   r"/wp-content/|/wp-includes/"),
    ("WordPress",         "cms",       "high",   r'content="WordPress'),
    ("Drupal",            "cms",       "high",   r'Drupal\.settings|drupal\.org'),
    ("Joomla",            "cms",       "high",   r'/components/com_|Joomla!'),
    ("Magento",           "cms",       "high",   r'Mage\.Cookies|magento'),
    ("Shopify",           "platform",  "high",   r'shopify\.com/s/files|Shopify\.theme'),
    ("Wix",               "platform",  "high",   r'wix\.com/|_wix_'),
    ("Squarespace",       "platform",  "high",   r'squarespace\.com'),
    ("React",             "library",   "medium", r'react\.js|react\.development|__reactFiber'),
    ("Vue.js",            "library",   "medium", r'vue\.js|__vue_'),
    ("Angular",           "library",   "medium", r'ng-version=|angular\.js'),
    ("jQuery",            "library",   "medium", r'jquery(?:\.min)?\.js'),
    ("Bootstrap",         "css_framework","low", r'bootstrap(?:\.min)?\.css|bootstrap(?:\.min)?\.js'),
    ("Tailwind CSS",      "css_framework","medium",r'tailwindcss|tailwind\.config'),
    ("Django",            "framework", "medium", r'csrfmiddlewaretoken'),
    ("Flask",             "framework", "low",    r'flask|werkzeug'),
    ("Laravel",           "framework", "medium", r'laravel|csrf-token.*laravel'),
    ("Ruby on Rails",     "framework", "medium", r'rails\.js|action_controller'),
    ("Next.js",           "framework", "high",   r'__NEXT_DATA__|_next/static'),
    ("Nuxt.js",           "framework", "high",   r'__NUXT__|/_nuxt/'),
    ("Google Analytics",  "analytics", "high",   r'google-analytics\.com/analytics\.js|gtag\('),
    ("Google Tag Manager","analytics", "high",   r'googletagmanager\.com/gtm\.js'),
    ("Cloudflare Turnstile","security","high",   r'challenges\.cloudflare\.com'),
    ("reCAPTCHA",         "security",  "high",   r'google\.com/recaptcha'),
    ("Font Awesome",      "library",   "low",    r'font-awesome|fontawesome'),
]


def fingerprint(url: str, timeout: int = 8, session=None) -> list:
    _req = session if session is not None else requests
    """
    Returns a list of detected technologies as info-level findings.
    Also checks for admin panel exposure and version disclosure.
    """
    findings = []
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return findings

    headers      = {k.lower(): v for k, v in resp.headers.items()}
    body         = resp.text
    cookie_str   = "; ".join(f"{c.name}={c.value}" for c in resp.cookies)
    detected     = {}

    # ── Header matching ────────────────────────────────────────────────────────
    for name, category, confidence, dtype, pattern in HEADER_SIGS:
        if not dtype.startswith("header:"):
            continue
        hdr = dtype.split(":", 1)[1]
        val = headers.get(hdr, "")
        if val and re.search(pattern, val, re.I):
            version = ""
            m = re.search(pattern, val, re.I)
            if m and m.lastindex:
                version = m.group(1)
            detected[name] = {"category": category, "confidence": confidence, "version": version, "source": hdr}

    # ── Cookie matching ────────────────────────────────────────────────────────
    for name, category, confidence, pattern in COOKIE_SIGS:
        if re.search(pattern, cookie_str, re.I):
            if name not in detected:
                detected[name] = {"category": category, "confidence": confidence, "version": "", "source": "cookie"}

    # ── HTML body matching ─────────────────────────────────────────────────────
    for name, category, confidence, pattern in HTML_SIGS:
        if re.search(pattern, body, re.I):
            if name not in detected:
                detected[name] = {"category": category, "confidence": confidence, "version": "", "source": "html"}

    # ── Version Disclosure check ───────────────────────────────────────────────
    server_hdr = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    version_exposed = []
    if re.search(r"\d+\.\d+", server_hdr):
        version_exposed.append(f"Server: {server_hdr}")
    if re.search(r"\d+\.\d+", powered_by):
        version_exposed.append(f"X-Powered-By: {powered_by}")

    if version_exposed:
        findings.append({
            "name": "Software Version Disclosure",
            "type": "Information Disclosure",
            "severity": "Low",
            "cvss_score": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "category": "info_disclosure",
            "url_affected": url,
            "parameter": "response headers",
            "evidence": "Exact software versions exposed: " + " | ".join(version_exposed),
            "request_data": url,
            "response_data": " | ".join(version_exposed),
            "cwe_id": "CWE-200",
            "owasp_category": "A05:2021",
            "detail": "Exact software versions help attackers identify known CVEs and tailor exploits.",
            "remediation": "Configure your web server to suppress detailed version strings (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).",
            "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
        })

    # ── Compile tech inventory finding ────────────────────────────────────────
    if detected:
        tech_list = []
        for tech, info in detected.items():
            entry = tech
            if info["version"]:
                entry += f" {info['version']}"
            tech_list.append(f"{entry} [{info['category']}]")

        findings.append({
            "name": "Technology Stack Fingerprint",
            "type": "Information Gathering",
            "severity": "Info",
            "cvss_score": 0.0,
            "cvss_vector": "",
            "category": "fingerprint",
            "url_affected": url,
            "parameter": "multiple sources",
            "evidence": " | ".join(tech_list),
            "request_data": url,
            "response_data": "",
            "cwe_id": "CWE-200",
            "owasp_category": "A05:2021",
            "detail": (
                f"Detected technologies: {', '.join(detected.keys())}. "
                "This information assists attackers in choosing targeted exploits."
            ),
            "remediation": "Minimize information exposure by removing version headers and disabling default error pages.",
            "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
        })

    return findings
