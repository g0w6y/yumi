import re
import yaml
from rich.table import Table
from rich.console import Console

console = Console()

class Scanner:
    def __init__(self, js_files):
        self.js_files = js_files
        self.rules = self.load_rules()

    def load_rules(self):
        with open("rules/secrets.yml", "r") as f:
            return yaml.safe_load(f)

    def scan(self):
        results = []
        for js_file in self.js_files:
            try:
                with httpx.Client() as client:
                    response = client.get(js_file)
                    content = response.text
                    for rule in self.rules:
                        matches = re.findall(rule["regex"], content)
                        for match in matches:
                            results.append({
                                "file": js_file,
                                "rule_id": rule["id"],
                                "name": rule["name"],
                                "match": match,
                                "severity": rule["severity"]
                            })
            except httpx.RequestError:
                pass  # Ignore errors for this example
        return results
