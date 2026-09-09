import argparse
from pathlib import Path

from .inventory import load_inventory
from .reporting import to_markdown
from .scoring import prioritize


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a prioritized attack-surface inventory from synthetic or exported asset data.")
    parser.add_argument("inventory", help="Path to JSON asset inventory")
    parser.add_argument("--output", default="attack-surface-report.md", help="Markdown report destination")
    args = parser.parse_args()

    assets = load_inventory(args.inventory)
    findings = prioritize(assets)
    Path(args.output).write_text(to_markdown(assets, findings), encoding="utf-8")
    print(f"Assessed {len(assets)} assets; report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
