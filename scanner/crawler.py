import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl(url):
    urls = set()
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        base = urlparse(url).netloc

        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            if urlparse(full_url).netloc == base:
                urls.add(full_url)

    except Exception:
        pass

    return list(urls)
