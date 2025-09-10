import httpx
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

class Fetch:
    def __init__(self, domains, logger, threads):
        self.domains = domains
        self.logger = logger
        self.threads = threads
        self.js_file_urls = set()

    async def _fetch_urls_from_domain(self, domain, client, progress, task):
        try:
            url = f"https://{domain}"
            response = await client.get(url, timeout=15, follow_redirects=True)
            soup = BeautifulSoup(response.text, "html.parser")
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                full_url = urljoin(str(response.url), src)
                self.js_file_urls.add(full_url)
        except Exception:
            pass 
        finally:
            progress.update(task, advance=1)

    async def discover_js_files(self):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("[cyan]Discovering JS...", total=len(self.domains))
            async with httpx.AsyncClient() as client:
                semaphore = asyncio.Semaphore(self.threads)
                tasks = []
                for domain in self.domains:
                    async def task_wrapper(d):
                        async with semaphore:
                            await self._fetch_urls_from_domain(d, client, progress, task)
                    tasks.append(task_wrapper(domain))
                await asyncio.gather(*tasks)
        return list(self.js_file_urls)

    async def _fetch_content(self, url, client, progress, task, content_map):
        try:
            response = await client.get(url, timeout=15)
            if "javascript" in response.headers.get("Content-Type", ""):
                content_map[url] = response.text
        except Exception:
            pass
        finally:
            progress.update(task, advance=1)

    async def fetch_js_content(self, urls):
        js_content_map = {}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("[green]Fetching content...", total=len(urls))
            async with httpx.AsyncClient() as client:
                semaphore = asyncio.Semaphore(self.threads)
                tasks = []
                for url in urls:
                    async def task_wrapper(u):
                        async with semaphore:
                            await self._fetch_content(u, client, progress, task, js_content_map)
                    tasks.append(task_wrapper(u))
                await asyncio.gather(*tasks)
        return js_content_map
