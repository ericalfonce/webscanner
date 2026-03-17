"""
MulikaScans — Information Disclosure Checks
Detects exposed sensitive files, directory listings, stack traces, etc.
"""

import requests
from urllib.parse import urljoin, urlparse

SENSITIVE_PATHS = [
    # ── Environment & Config ──────────────────────────────────────────────────
    ("/.env",                        "Environment variables file exposed"),
    ("/.env.local",                  ".env.local exposed"),
    ("/.env.production",             ".env.production exposed"),
    ("/.env.backup",                 ".env.backup exposed"),
    ("/.env.example",                ".env.example may disclose variables"),
    ("/config.php",                  "PHP configuration file exposed"),
    ("/config.yml",                  "YAML config file exposed"),
    ("/config.yaml",                 "YAML config file exposed"),
    ("/config.json",                 "JSON config file exposed"),
    ("/settings.py",                 "Django settings exposed"),
    ("/local_settings.py",           "Django local settings exposed"),
    ("/application.properties",      "Spring Boot properties exposed"),
    ("/application.yml",             "Spring Boot YAML config exposed"),
    # ── Source Control ────────────────────────────────────────────────────────
    ("/.git/config",                 "Git repository configuration exposed"),
    ("/.git/HEAD",                   "Git HEAD file exposed"),
    ("/.git/COMMIT_EDITMSG",         "Git commit message exposed"),
    ("/.git/refs/heads/main",        "Git refs exposed"),
    ("/.gitignore",                  ".gitignore may reveal directory structure"),
    ("/.svn/entries",                "SVN repository exposed"),
    ("/.hg/hgrc",                    "Mercurial config exposed"),
    # ── CMS Configs ───────────────────────────────────────────────────────────
    ("/wp-config.php",               "WordPress configuration exposed"),
    ("/wp-config.php.bak",           "WordPress config backup exposed"),
    ("/wp-login.php",                "WordPress login page accessible"),
    ("/wp-json/wp/v2/users",         "WordPress users API exposed"),
    ("/administrator/",              "Joomla admin panel accessible"),
    ("/sites/default/settings.php",  "Drupal settings exposed"),
    # ── PHP Diagnostics ───────────────────────────────────────────────────────
    ("/phpinfo.php",                 "PHP info page exposed"),
    ("/info.php",                    "PHP info page exposed"),
    ("/test.php",                    "PHP test page exposed"),
    ("/php.php",                     "PHP info exposed"),
    ("/.htaccess",                   "Apache .htaccess file exposed"),
    # ── Web Server Status ─────────────────────────────────────────────────────
    ("/server-status",               "Apache server-status page exposed"),
    ("/server-info",                 "Apache server-info page exposed"),
    ("/nginx_status",                "Nginx status page exposed"),
    ("/status",                      "Status endpoint exposed"),
    ("/health",                      "Health endpoint exposed"),
    ("/ping",                        "Ping endpoint exposed"),
    # ── API Docs ──────────────────────────────────────────────────────────────
    ("/api/swagger.json",            "Swagger/OpenAPI spec exposed"),
    ("/swagger.json",                "Swagger spec exposed"),
    ("/swagger-ui.html",             "Swagger UI exposed"),
    ("/swagger-ui",                  "Swagger UI exposed"),
    ("/api-docs",                    "API docs exposed"),
    ("/openapi.json",                "OpenAPI spec exposed"),
    ("/openapi.yaml",                "OpenAPI YAML spec exposed"),
    ("/docs",                        "API documentation exposed"),
    ("/redoc",                       "ReDoc API docs exposed"),
    # ── Spring Boot Actuator ──────────────────────────────────────────────────
    ("/actuator",                    "Spring Boot actuator exposed"),
    ("/actuator/env",                "Spring Boot env actuator exposed"),
    ("/actuator/health",             "Spring Boot health exposed"),
    ("/actuator/info",               "Spring Boot info exposed"),
    ("/actuator/beans",              "Spring Boot beans exposed"),
    ("/actuator/mappings",           "Spring Boot URL mappings exposed"),
    ("/actuator/httptrace",          "Spring Boot HTTP trace exposed"),
    ("/actuator/dump",               "Spring Boot thread dump exposed"),
    # ── Debug & Admin ─────────────────────────────────────────────────────────
    ("/debug",                       "Debug endpoint accessible"),
    ("/debug/pprof",                 "Go pprof debug endpoint exposed"),
    ("/console",                     "Framework console exposed (RCE risk)"),
    ("/admin",                       "Admin panel accessible"),
    ("/admin/",                      "Admin panel accessible"),
    ("/panel",                       "Admin panel accessible"),
    ("/dashboard",                   "Dashboard accessible"),
    ("/phpmyadmin",                  "phpMyAdmin exposed"),
    ("/phpmyadmin/",                 "phpMyAdmin exposed"),
    ("/pma",                         "phpMyAdmin exposed"),
    ("/adminer.php",                 "Adminer DB tool exposed"),
    # ── Backups & Exports ─────────────────────────────────────────────────────
    ("/backup",                      "Backup directory accessible"),
    ("/backup/",                     "Backup directory accessible"),
    ("/backup.zip",                  "Backup archive exposed"),
    ("/backup.tar.gz",               "Backup tarball exposed"),
    ("/backup.sql",                  "Database backup exposed"),
    ("/db_backup.sql",               "Database backup exposed"),
    ("/database.sql",                "Database dump exposed"),
    ("/dump.sql",                    "Database dump exposed"),
    ("/site.zip",                    "Site archive exposed"),
    ("/www.zip",                     "www archive exposed"),
    # ── Credentials / Keys ────────────────────────────────────────────────────
    ("/id_rsa",                      "Private SSH key exposed"),
    ("/id_rsa.pub",                  "SSH public key exposed"),
    ("/.ssh/id_rsa",                 "SSH private key exposed"),
    ("/private.key",                 "Private key exposed"),
    ("/server.key",                  "Server private key exposed"),
    ("/credentials.json",            "Credentials file exposed"),
    ("/secrets.json",                "Secrets file exposed"),
    ("/keys.json",                   "API keys exposed"),
    # ── Logs ─────────────────────────────────────────────────────────────────
    ("/logs",                        "Logs directory accessible"),
    ("/log",                         "Log file accessible"),
    ("/error.log",                   "Error log exposed"),
    ("/access.log",                  "Access log exposed"),
    ("/debug.log",                   "Debug log exposed"),
    ("/laravel.log",                 "Laravel log exposed"),
    ("/storage/logs/laravel.log",    "Laravel log exposed"),
    # ── Misc ──────────────────────────────────────────────────────────────────
    ("/.DS_Store",                   ".DS_Store file exposed (macOS metadata)"),
    ("/crossdomain.xml",             "Flash cross-domain policy exposed"),
    ("/clientaccesspolicy.xml",      "Silverlight cross-domain policy exposed"),
    ("/robots.txt",                  "robots.txt may disclose hidden paths"),
    ("/sitemap.xml",                 "Sitemap may disclose internal URLs"),
    ("/web.config",                  "ASP.NET web.config exposed"),
    ("/web.config.bak",              "ASP.NET web.config backup exposed"),
    ("/Dockerfile",                  "Dockerfile exposed"),
    ("/docker-compose.yml",          "Docker Compose config exposed"),
    ("/Makefile",                    "Makefile exposed — may reveal build scripts"),
    ("/package.json",                "package.json exposed — lists dependencies"),
    ("/composer.json",               "composer.json exposed — lists dependencies"),
    ("/Gemfile",                     "Gemfile exposed"),
    ("/requirements.txt",            "Python requirements exposed"),
    ("/.well-known/security.txt",    "Security.txt present (informational)"),
]

# Signatures that indicate stack traces / framework errors
ERROR_SIGNATURES = [
    ("traceback (most recent call last)", "Python stack trace exposed"),
    ("syntaxerror", "Python syntax error exposed"),
    ("at system.web.", "ASP.NET exception exposed"),
    ("java.lang.", "Java exception exposed"),
    ("php fatal error", "PHP fatal error exposed"),
    ("warning: ", "PHP warning exposed"),
    ("mysql_fetch_array", "MySQL error exposed"),
    ("pg_query", "PostgreSQL error exposed"),
    ("sqlstate", "SQL state error exposed"),
    ("applicationerror", "Application error page exposed"),
]


def check_info_disclosure(url, timeout=8):
    findings = []
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}
    base_url = _base_url(url)

    for path, description in SENSITIVE_PATHS:
        test_url = urljoin(base_url, path)
        try:
            resp = requests.get(test_url, timeout=timeout,
                                allow_redirects=False, headers=headers)
            if resp.status_code in (200, 301, 302, 403):
                severity = _path_severity(path, resp.status_code, resp.text)
                if severity:
                    findings.append({
                        "name": f"Sensitive File Exposed: {path}",
                        "type": "Information Disclosure",
                        "severity": severity,
                        "cvss_score": _cvss_for_severity(severity),
                        "category": "info_disclosure",
                        "url_affected": test_url,
                        "parameter": path,
                        "evidence": f"HTTP {resp.status_code}: {description}",
                        "cwe_id": "CWE-200",
                        "owasp_category": "A05:2021",
                        "detail": description,
                        "remediation": (
                            f"Restrict access to '{path}'. Remove or relocate sensitive files "
                            "outside the web root. Use .htaccess or server config to deny access."
                        ),
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/",
                        ],
                    })
        except requests.RequestException:
            pass

    # Check for directory listing on target URL
    try:
        resp = requests.get(url, timeout=timeout, headers=headers)
        body_lower = resp.text.lower()

        if "index of /" in body_lower or "directory listing" in body_lower:
            findings.append({
                "name": "Directory Listing Enabled",
                "type": "Information Disclosure",
                "severity": "Medium",
                "cvss_score": 5.3,
                "category": "info_disclosure",
                "url_affected": url,
                "parameter": "directory",
                "evidence": "Server returns directory index page revealing file structure",
                "cwe_id": "CWE-548",
                "owasp_category": "A05:2021",
                "detail": "Directory listing is enabled — internal file structure exposed",
                "remediation": (
                    "Disable directory listing in your web server configuration. "
                    "Apache: Options -Indexes. Nginx: Remove 'autoindex on'."
                ),
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration",
                ],
            })

        # Check for exposed stack traces / error pages
        for sig, description in ERROR_SIGNATURES:
            if sig in body_lower:
                findings.append({
                    "name": "Application Error / Stack Trace Exposed",
                    "type": "Information Disclosure",
                    "severity": "Medium",
                    "cvss_score": 5.3,
                    "category": "info_disclosure",
                    "url_affected": url,
                    "parameter": "error_page",
                    "evidence": f"'{sig}' found in response — {description}",
                    "cwe_id": "CWE-209",
                    "owasp_category": "A05:2021",
                    "detail": description,
                    "remediation": (
                        "Disable debug mode in production. Configure custom error pages that "
                        "do not reveal stack traces or framework details."
                    ),
                    "references": [
                        "https://owasp.org/www-community/Improper_Error_Handling",
                    ],
                })
                break

    except requests.RequestException:
        pass

    return findings


def _base_url(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _path_severity(path, status_code, body):
    """Determine if this is a real exposure vs. a 404-style redirect."""
    if status_code == 403:
        return "Info"  # Exists but access denied — still worth noting
    if status_code in (301, 302):
        return None  # Redirect — probably a login redirect, not exposed
    body_lower = body.lower()
    # High-value secrets
    if any(p in path for p in [".env", "config", "backup", ".git", "db_backup"]):
        if len(body) > 20:
            return "High"
    if "phpinfo" in path and "php version" in body_lower:
        return "High"
    if "server-status" in path and "apache" in body_lower:
        return "Medium"
    if "swagger" in path or "actuator" in path:
        return "Medium"
    if status_code == 200 and len(body) > 10:
        return "Low"
    return None


def _cvss_for_severity(severity):
    return {"Critical": 9.0, "High": 7.5, "Medium": 5.3, "Low": 3.1, "Info": 0.0}.get(severity, 0.0)
