import argparse
import asyncio
from yumi.core.engine import Engine
from rich.console import Console

def display_banner():
    try:
        with open("assets/logo.txt", "r") as f:
            logo = f.read()
            console = Console()
            console.print(f"[bold cyan]{logo}[/bold cyan]")
            console.print("         [italic yellow]The intelligent JS Recon Engine[/italic yellow]\n")
    except FileNotFoundError:
        print("Yumi v2.0")


def start():
    display_banner()
    parser = argparse.ArgumentParser(description="Yumi - An intelligent, asynchronous JS Recon Engine")
    parser.add_argument("domain", help="Target domain for reconnaissance (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output file to save the JSON report (e.g., report.json)", default="report.json")
    parser.add_argument("-t", "--threads", help="Number of concurrent threads for fetching", type=int, default=20)
    args = parser.parse_args()

    engine = Engine(args.domain, args.output, args.threads)
    asyncio.run(engine.run())

if __name__ == "__main__":
    start()
