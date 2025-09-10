import json
from rich.table import Table
from rich.console import Console

console = Console()

class Reporter:
    def __init__(self, results):
        self.results = results

    def generate_json_report(self, filename):
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)

    def print_console_report(self):
        if not self.results:
            return
            
        table = Table(title="Yumi Scan Results")
        table.add_column("File URL", style="cyan", no_wrap=False)
        table.add_column("Rule Name", style="magenta")
        table.add_column("Match", style="green")
        table.add_column("Severity", style="red")

        for result in self.results:
            table.add_row(result["file_url"], result["name"], result["match"], result["severity"])

        console.print(table)
