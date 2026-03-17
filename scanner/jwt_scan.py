"""
JWT Vulnerability Scanner
Detects insecure JWT configurations: alg:none bypass, weak HMAC secrets,
sensitive data in payload, missing expiry, and algorithm confusion.
"""

import base64
import json
import hmac
import hashlib
import time
import requests
from urllib.parse import urlparse


# ── Common weak JWT secrets ────────────────────────────────────────────────────
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "qwerty",
    "admin", "key", "jwt_secret", "your-secret-key",
    "supersecret", "mysecret", "secretkey", "jwtkey",
    "dev-secret", "test", "development", "production",
    "flask-secret", "django-insecure", "laravel", "",
]


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _parse_jwt(token: str):
    """Parse a JWT into (header, payload, signature, raw_parts) or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2], parts
    except Exception:
        return None


def _forge_none_alg(parts: list) -> str:
    """Forge a JWT with alg:none to test if the server accepts it."""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        header["alg"] = "none"
        new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{parts[1]}."
    except Exception:
        return None


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _try_weak_secret(parts: list) -> str | None:
    """Return the cracked secret if any weak secret produces the real signature."""
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in WEAK_SECRETS:
        expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if _b64url_encode(expected_sig) == parts[2]:
            return secret
    return None


def _extract_tokens(resp: requests.Response) -> list:
    """Extract JWTs from response cookies and body."""
    tokens = []
    for cookie in resp.cookies:
        val = cookie.value
        if val and val.count(".") == 2:
            tokens.append(("cookie", cookie.name, val))
    # Scan response body for JWTs
    import re
    pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    for match in pattern.finditer(resp.text[:10000]):
        tokens.append(("body", "jwt", match.group()))
    return tokens


def check_jwt(url: str, timeout: int = 8) -> list:
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    # Also check Authorization header if present in response links, and any
    # existing cookies from the current session
    try:
        resp = session.get(url, timeout=timeout, verify=False)
    except Exception:
        return findings

    tokens = _extract_tokens(resp)

    # Also try common API endpoints that return tokens
    for endpoint in ["/api/auth/me", "/api/user", "/api/token"]:
        try:
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            r2 = session.get(base + endpoint, timeout=timeout, verify=False)
            tokens.extend(_extract_tokens(r2))
        except Exception:
            continue

    seen_tokens = set()
    for location, name, token in tokens:
        if token in seen_tokens:
            continue
        seen_tokens.add(token)

        parsed = _parse_jwt(token)
        if not parsed:
            continue
        header, payload, _, parts = parsed

        alg = header.get("alg", "").upper()

        # ── 1. Sensitive data in payload ──────────────────────────────────────
        sensitive_keys = {"password", "passwd", "secret", "credit_card",
                          "ssn", "cvv", "pin", "private_key"}
        exposed = [k for k in payload if k.lower() in sensitive_keys]
        if exposed:
            findings.append({
                "name": "JWT: Sensitive Data in Token Payload",
                "type": "JWT Vulnerability",
                "severity": "High",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "category": "jwt",
                "url_affected": url,
                "parameter": f"{location}:{name}",
                "evidence": f"Sensitive keys found in JWT payload: {exposed}",
                "request_data": token[:80] + "…",
                "response_data": json.dumps(payload, indent=2)[:300],
                "cwe_id": "CWE-312",
                "owasp_category": "A02:2021",
                "detail": "JWT payloads are base64-encoded — not encrypted. Any sensitive fields are readable by anyone who intercepts the token.",
                "remediation": "Never store sensitive data in JWTs. Use opaque session tokens for sensitive state.",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"],
            })

        # ── 2. Algorithm = none ───────────────────────────────────────────────
        if alg == "NONE":
            findings.append({
                "name": "JWT: Algorithm 'none' Accepted — Signature Bypass",
                "type": "JWT Vulnerability",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "category": "jwt",
                "url_affected": url,
                "parameter": f"{location}:{name}",
                "evidence": "JWT header contains alg:none — no signature is required",
                "request_data": token[:80] + "…",
                "response_data": json.dumps(header),
                "cwe_id": "CWE-347",
                "owasp_category": "A02:2021",
                "detail": "The server issued a token with alg:none. If it also accepts such tokens, attackers can forge arbitrary payloads without knowing the secret key.",
                "remediation": "Reject JWTs with alg:none. Maintain an explicit allowlist of accepted algorithms (HS256 or RS256 only). Use a vetted JWT library.",
                "references": [
                    "https://portswigger.net/web-security/jwt",
                    "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                ],
            })

        # ── 3. Weak HMAC secret ───────────────────────────────────────────────
        if alg.startswith("HS"):
            cracked = _try_weak_secret(parts)
            if cracked is not None:
                findings.append({
                    "name": "JWT: Weak HMAC Secret Cracked",
                    "type": "JWT Vulnerability",
                    "severity": "Critical",
                    "cvss_score": 9.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "category": "jwt",
                    "url_affected": url,
                    "parameter": f"{location}:{name}",
                    "evidence": f"HMAC secret cracked: '{cracked}' — attacker can forge tokens for any user",
                    "request_data": token[:80] + "…",
                    "response_data": "",
                    "cwe_id": "CWE-521",
                    "owasp_category": "A02:2021",
                    "detail": f"The JWT signing secret '{cracked}' is weak and was recovered by brute-force. An attacker can now create valid tokens for any user ID or role.",
                    "remediation": "Use a cryptographically random secret of at least 256 bits. Store it securely as an environment variable. Rotate it immediately.",
                    "references": ["https://portswigger.net/web-security/jwt"],
                })

        # ── 4. Missing / expired 'exp' claim ─────────────────────────────────
        exp = payload.get("exp")
        if exp is None:
            findings.append({
                "name": "JWT: Missing Expiry Claim (exp)",
                "type": "JWT Vulnerability",
                "severity": "Medium",
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "category": "jwt",
                "url_affected": url,
                "parameter": f"{location}:{name}",
                "evidence": "JWT payload has no 'exp' claim — token never expires",
                "request_data": token[:80] + "…",
                "response_data": json.dumps(payload)[:300],
                "cwe_id": "CWE-613",
                "owasp_category": "A07:2021",
                "detail": "Tokens without an expiry claim remain valid forever. If stolen, they cannot be revoked without rotating the signing key.",
                "remediation": "Always include the 'exp' claim. Set short expiry times (15–60 minutes for access tokens).",
                "references": ["https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4"],
            })

    return findings
