from rich.console import Console

class Logger:
    def __init__(self):
        self.console = Console()

    def info(self, message):
        self.console.log(f"[bold blue]INFO[/bold blue] - {message}")

    def warning(self, message):
        self.console.log(f"[bold yellow]WARNING[/bold yellow] - {message}")

    def error(self, message):
        self.console.log(f"[bold red]ERROR[/bold red] - {message}")
