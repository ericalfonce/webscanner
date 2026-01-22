from scanner.crawler import crawl
from scanner.sqli import test_sqli
from scanner.xss import test_xss
from scanner.headers import check_headers

def run_scan(target_url):
    findings = []

    urls = crawl(target_url)
    urls.append(target_url)

    for url in urls:
        findings.extend(check_headers(url))
        findings.extend(test_xss(url))
        findings.extend(test_sqli(url))

    return findings
