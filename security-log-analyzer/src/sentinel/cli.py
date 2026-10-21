"""Command-line interface."""
import argparse
import json
from .detector import detect, load_events


def main():
    parser = argparse.ArgumentParser(description="Analyze authorized authentication CSV logs")
    parser.add_argument("csv_path")
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--window", type=int, default=10, help="Sliding window in minutes")
    args = parser.parse_args()
    try:
        alerts = detect(load_events(args.csv_path), window_minutes=args.window)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.format == "json":
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    elif not alerts:
        print("No alerts.")
    else:
        print(f"{'RULE':24} {'SOURCE IP':17} {'USER':15} {'COUNT':5} DETAIL")
        for a in alerts:
            print(f"{a.rule:24} {a.source_ip:17} {a.username:15} {a.count:<5} {a.detail}")


if __name__ == "__main__":
    main()
