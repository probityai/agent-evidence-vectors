"""Read a case and its selected policy without mutating their bytes."""

import argparse
import json
import sys
from pathlib import Path

from .reader import InputError, assess


def main() -> int:
    """Return 2 for malformed input; every evaluated report retains all axes."""
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    read = commands.add_parser("read")
    read.add_argument("case", type=Path)
    read.add_argument("--policy", required=True, type=Path)
    controls = commands.add_parser("controls")
    controls.add_argument("--output", required=True, type=Path)
    bridge = commands.add_parser("coverage-bridge")
    bridge.add_argument("--output", required=True, type=Path)
    frequency = commands.add_parser("frequency-read")
    frequency.add_argument("case", type=Path)
    frequency_controls = commands.add_parser("frequency-controls")
    frequency_controls.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "controls":
            from .runner import run_controls

            result = run_controls(args.output)
        elif args.command == "coverage-bridge":
            from .coverage_bridge import run_bridge

            result = run_bridge(args.output)
        elif args.command == "frequency-controls":
            from .frequency_claims import run_supplied_controls

            result = run_supplied_controls(args.output)
        elif args.command == "frequency-read":
            from .frequency_claims import assess_supplied_claims

            result = assess_supplied_claims(args.case.read_bytes())
        else:
            result = assess(args.case.read_bytes(), args.policy.read_bytes())
    except (OSError, InputError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(
        result.get("passed", 0) != result.get("total", 0)
        or bool(result.get("vectorsFailures"))
        or result.get("vectorsExecuted", result.get("total", 0)) != result.get("total", 0)
    )


if __name__ == "__main__":
    raise SystemExit(main())
