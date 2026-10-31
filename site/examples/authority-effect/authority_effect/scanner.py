"""A reduced process fixture; this does not scan real source or credentials."""

import argparse

MODES = ("complete", "truncation-zero", "truncation-one", "silent-truncation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=MODES)
    args = parser.parse_args()
    scanned = ["unit-a", "unit-b", "unit-c"] if args.mode == "complete" else ["unit-a"]
    for unit in scanned:
        print(f"selected unit: {unit}")
    if args.mode.startswith("truncation-"):
        print("truncated: 2 unit(s)")
    print("no findings in scanned units")
    return int(args.mode == "truncation-one")


if __name__ == "__main__":
    raise SystemExit(main())
