import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.progress import track

class Fetch:
    def __init__(self, domains):
        self.domains = domains
        self.js_files = []

    def fetch_all(self):
        for domain in track(self.domains, description="Fetching JS files..."):
            self.fetch_from_domain(domain)
        return self.js_files

    def fetch_from_domain(self, domain):
        try:
            with httpx.Client() as client:
                response = client.get(f"http://{domain}")
                soup = BeautifulSoup(response.text, "html.parser")
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        self.js_files.append(urljoin(response.url, src))
        except httpx.RequestError as e:
            print(f"Error fetching from {domain}: {e}")
