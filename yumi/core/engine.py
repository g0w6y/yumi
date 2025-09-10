from yumi.modules.recon import Recon
from yumi.modules.fetch import Fetch
from yumi.analysis.scanner import Scanner
from yumi.reporting.reporter import Reporter
from yumi.utils.logger import Logger

class Engine:
    def __init__(self, domain, output_file, threads):
        self.domain = domain
        self.output_file = output_file
        self.threads = threads
        self.logger = Logger()

    async def run(self):
        self.logger.info(f"Starting reconnaissance on {self.domain}...")
        recon = Recon(self.domain, self.logger)
        subdomains = await recon.enumerate_subdomains()
        
        if not subdomains:
            self.logger.warning(f"No subdomains found for {self.domain}. Exiting.")
            return

        self.logger.info(f"Found {len(subdomains)} subdomains. Fetching JavaScript file URLs...")
        fetcher = Fetch(subdomains, self.logger, self.threads)
        js_file_urls = await fetcher.discover_js_files()

        if not js_file_urls:
            self.logger.warning("No JavaScript files found to analyze. Exiting.")
            return
            
        self.logger.info(f"Found {len(js_file_urls)} unique JS files. Fetching content...")
        js_content_map = await fetcher.fetch_js_content(js_file_urls)

        self.logger.info("Scanning JavaScript files for secrets...")
        scanner = Scanner(js_content_map)
        results = scanner.scan()

        self.logger.info(f"Found {len(results)} potential secrets.")
        if results:
            reporter = Reporter(results)
            reporter.generate_json_report(self.output_file)
            reporter.print_console_report()
            self.logger.info(f"Report saved to {self.output_file}")
        else:
            self.logger.info("No secrets found matching the rules.")

        self.logger.info("Scan complete.")
