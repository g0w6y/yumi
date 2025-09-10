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
        table = Table(title="Yumi Scan Results")
        table.add_column("File", style="cyan")
        table.add_column("Rule Name", style="magenta")
        table.add_column("Match", style="green")
        table.add_column("Severity", style="red")

        for result in self.results:
            table.add_row(result["file"], result["name"], result["match"], result["severity"])

        console.print(table)
