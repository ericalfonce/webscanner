import requests

def check_headers(url):
    findings = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

        for header in security_headers:
            if header not in headers:
                findings.append({
                    "url": url,
                    "type": "Missing Security Header",
                    "detail": f"{header} is missing",
                    "severity": "Low"
                })

    except Exception:
        pass

    return findings
