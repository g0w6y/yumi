import argparse
from yumi.core.engine import Engine

def start():
    parser = argparse.ArgumentParser(description="Yumi - An intelligent, asynchronous JS Recon Engine")
    parser.add_argument("domain", help="Target domain for reconnaissance")
    args = parser.parse_args()

    engine = Engine(args.domain)
    engine.run()

if __name__ == "__main__":
    start()
