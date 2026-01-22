import requests

def test_xss(url):
    findings = []
    payload = "<script>alert(1)</script>"

    if "?" not in url:
        return findings

    test_url = url + payload

    try:
        response = requests.get(test_url, timeout=5)
        if payload in response.text:
            findings.append({
                "url": url,
                "type": "Reflected XSS",
                "detail": "Payload reflected in response",
                "severity": "Medium"
            })

    except Exception:
        pass

    return findings
