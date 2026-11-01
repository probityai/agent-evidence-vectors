"""The single installed entry point; configuration selects trusted commands."""
import argparse
import json
import sys
from pathlib import Path
from .reader import Admission, Limits, Refused, read_record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    parser.add_argument("--limits", type=Path, required=True)
    args = parser.parse_args()
    try:
        selected = Admission(args.go, args.admission, args.capture_dir, Limits.from_file(args.limits))
        result = read_record(args.records, args.record, selected)
    except Refused as error:
        print(json.dumps({"status": "refused", "error_class": error.code, "detail": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
