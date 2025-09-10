from yumi.modules.recon import Recon
from yumi.modules.fetch import Fetch
from yumi.analysis.scanner import Scanner
from yumi.reporting.reporter import Reporter
from yumi.utils.logger import Logger

class Engine:
    def __init__(self, domain):
        self.domain = domain
        self.logger = Logger()

    def run(self):
        self.logger.info(f"Starting reconnaissance on {self.domain}...")
        recon = Recon(self.domain)
        subdomains = recon.enumerate_subdomains()

        self.logger.info("Fetching JavaScript files...")
        fetch = Fetch(subdomains)
        js_files = fetch.fetch_all()

        self.logger.info("Scanning JavaScript files for secrets...")
        scanner = Scanner(js_files)
        results = scanner.scan()

        self.logger.info("Generating report...")
        reporter = Reporter(results)
        reporter.generate_json_report("report.json")
        reporter.print_console_report()

        self.logger.info("Scan complete.")
