"""
MulikaScans — Web Crawler
Extracts in-scope URLs and forms from a target web application.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl(url, max_pages=50, timeout=8, session=None):
    _req = session if session is not None else requests
    """
    Crawl the target URL and return a list of discovered in-scope URLs.
    Respects max_pages limit (plan-dependent).
    """
    visited = set()
    queue = [url]
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}
    base_netloc = urlparse(url).netloc

    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        try:
            resp = _req.get(current, timeout=timeout,
                                allow_redirects=True, headers=headers)
            soup = BeautifulSoup(resp.text, "html.parser")

            for tag in soup.find_all(["a", "form", "script", "link", "img"]):
                raw = tag.get("href") or tag.get("src") or tag.get("action")
                if not raw or not isinstance(raw, str):
                    continue
                full_url = urljoin(current, raw)
                parsed = urlparse(full_url)
                # Stay in-scope (same domain, http/https only)
                if parsed.netloc == base_netloc and parsed.scheme in ("http", "https"):
                    clean = parsed._replace(fragment="").geturl()
                    if clean not in visited:
                        queue.append(clean)

        except requests.RequestException:
            pass

    return list(visited)


def extract_forms(url, timeout=8):
    """Extract all forms and their input fields from a URL."""
    forms = []
    headers = {"User-Agent": "MulikaScans/1.0 (Security Scanner)"}
    try:
        resp = _req.get(url, timeout=timeout, headers=headers)
        soup = BeautifulSoup(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = str(form.get("action") or "")
            method = str(form.get("method", "get") or "get").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                inp_type = inp.get("type", "text")
                if name:
                    inputs.append({"name": name, "type": inp_type})
            forms.append({
                "action": urljoin(url, action) if action else url,
                "method": method,
                "inputs": inputs,
            })
    except requests.RequestException:
        pass
    return forms
