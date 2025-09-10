import httpx
import asyncio

class Recon:
    def __init__(self, domain, logger):
        self.domain = domain
        self.logger = logger
        self.subdomains = set()

    async def enumerate_subdomains(self):
        self.logger.info(f"Querying crt.sh for subdomains of {self.domain}")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    name_value = item.get('name_value')
                    if name_value:
                        subdomains = name_value.split('\n')
                        for sub in subdomains:
                            if sub.endswith(f".{self.domain}") and not sub.startswith('*'):
                                self.subdomains.add(sub.strip())
                self.subdomains.add(self.domain) 
                return list(self.subdomains)
            else:
                self.logger.error(f"Failed to retrieve subdomains from crt.sh, status code: {response.status_code}")
                return [self.domain]
        except (httpx.RequestError, Exception) as e:
            self.logger.error(f"An error occurred while querying crt.sh: {e}")
            self.logger.warning("Falling back to scanning the main domain only.")
            return [self.domain]
