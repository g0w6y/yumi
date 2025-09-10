import re
import yaml
import jsbeautifier
from yumi.config import JSBEAUTIFIER_OPTIONS

class Scanner:
    def __init__(self, js_content_map):
        self.js_content_map = js_content_map
        self.rules = self.load_rules()

    def load_rules(self):
        try:
            with open("rules/secrets.yml", "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print("Error: rules/secrets.yml not found.")
            return []

    def scan(self):
        results = []
        for url, content in self.js_content_map.items():

            beautified_content = jsbeautifier.beautify(content, JSBEAUTIFIER_OPTIONS)
            
            for rule in self.rules:
                try:
                    matches = re.finditer(rule["regex"], beautified_content)
                    for match in matches:
                     
                        secret = match.group(2) if "generic-secret" in rule["id"] and len(match.groups()) > 1 else match.group(0)
                        
                        results.append({
                            "file_url": url,
                            "rule_id": rule["id"],
                            "name": rule["name"],
                            "match": secret,
                            "severity": rule["severity"]
                        })
                except re.error as e:
                    print(f"Regex error in rule {rule['id']}: {e}")
                    continue
        return results
