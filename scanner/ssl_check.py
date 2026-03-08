"""
MulikaScans — SSL/TLS Configuration Checker
Checks certificate validity, expiry, weak protocols, and HSTS.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl(url, timeout=8):
    findings = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        findings.append({
            "name": "Unencrypted HTTP Connection",
            "type": "No HTTPS",
            "severity": "High",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "category": "ssl",
            "url_affected": url,
            "parameter": "protocol",
            "evidence": "Target serves content over plain HTTP without TLS encryption",
            "cwe_id": "CWE-319",
            "owasp_category": "A02:2021",
            "detail": "Site is not using HTTPS",
            "remediation": (
                "Obtain a TLS certificate (free options: Let's Encrypt) and configure your "
                "web server to serve all traffic over HTTPS. Redirect HTTP to HTTPS. "
                "Enable HSTS to prevent protocol downgrade attacks."
            ),
            "references": [
                "https://letsencrypt.org/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
            ],
        })
        return findings

    hostname = parsed.hostname or ""
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, _, key_bits = ssock.cipher() or ("unknown", None, 0)

                # Check certificate expiry
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_after = not_after.replace(tzinfo=timezone.utc)
                    days_remaining = (not_after - datetime.now(timezone.utc)).days

                    if days_remaining < 0:
                        findings.append({
                            "name": "SSL Certificate Expired",
                            "type": "SSL/TLS Issue",
                            "severity": "Critical",
                            "cvss_score": 9.3,
                            "category": "ssl",
                            "url_affected": url,
                            "parameter": "certificate",
                            "evidence": f"Certificate expired on {not_after.strftime('%Y-%m-%d')}",
                            "cwe_id": "CWE-298",
                            "owasp_category": "A02:2021",
                            "detail": "SSL certificate has expired",
                            "remediation": "Renew the SSL certificate immediately. Consider automating renewal with Let's Encrypt / certbot.",
                            "references": ["https://letsencrypt.org/docs/"],
                        })
                    elif days_remaining < 30:
                        findings.append({
                            "name": "SSL Certificate Expiring Soon",
                            "type": "SSL/TLS Issue",
                            "severity": "Medium",
                            "cvss_score": 4.3,
                            "category": "ssl",
                            "url_affected": url,
                            "parameter": "certificate",
                            "evidence": f"Certificate expires in {days_remaining} days ({not_after.strftime('%Y-%m-%d')})",
                            "cwe_id": "CWE-298",
                            "owasp_category": "A02:2021",
                            "detail": f"SSL certificate expires in {days_remaining} days",
                            "remediation": "Renew the SSL certificate before it expires to avoid service disruption.",
                            "references": ["https://letsencrypt.org/docs/"],
                        })

                # Check for weak protocol
                if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "name": f"Weak TLS Protocol: {protocol}",
                        "type": "SSL/TLS Issue",
                        "severity": "High",
                        "cvss_score": 7.4,
                        "category": "ssl",
                        "url_affected": url,
                        "parameter": "tls_version",
                        "evidence": f"Server negotiated {protocol}, which has known vulnerabilities",
                        "cwe_id": "CWE-326",
                        "owasp_category": "A02:2021",
                        "detail": f"Server supports deprecated TLS version {protocol}",
                        "remediation": (
                            "Disable TLS 1.0 and TLS 1.1 in your server configuration. "
                            "Support only TLS 1.2 and TLS 1.3."
                        ),
                        "references": [
                            "https://www.openssl.org/docs/",
                            "https://ssl-config.mozilla.org/",
                        ],
                    })

                # Check for weak cipher
                if key_bits and int(key_bits) < 128:
                    findings.append({
                        "name": "Weak Cipher Suite",
                        "type": "SSL/TLS Issue",
                        "severity": "High",
                        "cvss_score": 7.4,
                        "category": "ssl",
                        "url_affected": url,
                        "parameter": "cipher",
                        "evidence": f"Cipher '{cipher_name}' uses only {key_bits}-bit key",
                        "cwe_id": "CWE-326",
                        "owasp_category": "A02:2021",
                        "detail": f"Weak cipher suite detected: {cipher_name}",
                        "remediation": "Configure your server to use only strong cipher suites (AES-256-GCM, CHACHA20-POLY1305). Use Mozilla SSL Config Generator.",
                        "references": ["https://ssl-config.mozilla.org/"],
                    })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "name": "SSL Certificate Verification Failed",
            "type": "SSL/TLS Issue",
            "severity": "High",
            "cvss_score": 7.4,
            "category": "ssl",
            "url_affected": url,
            "parameter": "certificate",
            "evidence": str(e),
            "cwe_id": "CWE-295",
            "owasp_category": "A02:2021",
            "detail": "SSL certificate could not be verified (self-signed or invalid CA)",
            "remediation": "Install a certificate from a trusted Certificate Authority (CA). Free options: Let's Encrypt.",
            "references": ["https://letsencrypt.org/"],
        })
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return findings
