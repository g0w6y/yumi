import httpx
from rich.console import Console

console = Console()

class Recon:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def enumerate_subdomains(self):
    
        self.subdomains.add(self.domain)
        self.subdomains.add(f"www.{self.domain}")
        self.subdomains.add(f"dev.{self.domain}")
        self.subdomains.add(f"api.{self.domain}")

        console.log(f"Found {len(self.subdomains)} subdomains.")
        return list(self.subdomains)
