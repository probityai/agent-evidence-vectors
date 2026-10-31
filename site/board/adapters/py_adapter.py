#!/usr/bin/env python3
"""Answer the a2a-jcs-v01 external-verifier contract for one Python function.

    py_adapter.py --file PATH|--repo PATH --module M --func F [--text] TARGET INPUT.json

The harness runs `<command> <target> <input.json>` once per vector. Exit 0 and
`{"canonical_utf8_hex": ...}` on the last stdout line means the function returned bytes
(or text, encoded as UTF-8). Exit 1 means the function raised: a refusal. Exit 2 means the
adapter itself could not run (bad usage, import failure, wrong target), which the harness
scores as errored, so a broken import never reads as a refusal.
"""
import argparse
import importlib
import importlib.util
import json
import pathlib
import sys


def load(args):
    if args.file:
        path = pathlib.Path(args.file).resolve()
        sys.path.insert(0, str(path.parent))
        spec = importlib.util.spec_from_file_location("board_target", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["board_target"] = module
        spec.loader.exec_module(module)
    else:
        sys.path.insert(0, args.repo)
        module = importlib.import_module(args.module)
    return getattr(module, args.func)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file")
    parser.add_argument("--repo")
    parser.add_argument("--module")
    parser.add_argument("--func", required=True)
    parser.add_argument("--text", action="store_true")
    parser.add_argument("target")
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        if args.target != "rfc8785":
            raise ValueError("adapter provides target rfc8785 only")
        fn = load(args)
        with open(args.input, encoding="utf-8") as handle:
            raw = handle.read()
        value = raw if args.text else json.loads(raw)
    except BaseException as exc:  # noqa: BLE001 - an adapter failure is exit 2, never a refusal
        print(f"adapter-error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        out = fn(value)
        if isinstance(out, str):
            out = out.encode("utf-8")
    except BaseException as exc:  # noqa: BLE001 - the implementation raised: a refusal
        print(f"refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps({"canonical_utf8_hex": out.hex()}))


if __name__ == "__main__":
    main()
