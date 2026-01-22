import requests

def test_sqli(url):
    findings = []
    payloads = ["'", "' OR '1'='1"]

    if "?" not in url:
        return findings

    for payload in payloads:
        try:
            test_url = url + payload
            response = requests.get(test_url, timeout=5)

            errors = [
                "sql syntax",
                "mysql_fetch",
                "ORA-",
                "unterminated"
            ]

            for error in errors:
                if error.lower() in response.text.lower():
                    findings.append({
                        "url": url,
                        "type": "SQL Injection",
                        "detail": "Possible SQL error detected",
                        "severity": "High"
                    })
                    return findings

        except Exception:
            pass

    return findings
