"""Command line.

``agent-evidence-admission digest-check <document> <artifact>``: exit 0 when the artifact has a
digest the document names, 1 when it does not (or the document names none), 2 when the document
or the artifact could not be read.

``agent-evidence-admission coverage-check <document> --required <list>``: exit 0 when every
required class is accounted for, 1 when any is missing, doubly selected, or not assessed with no
reason and no covering reference, 2 when the document or the list could not be read.

``agent-evidence-admission generate <admit-list> --out <dir>``: write the MCP allowlist each
client enforces natively; exit 0 when every server was rendered for every client asked for, 1 when
a client could not express a server exactly (the other files are still written), 2 when the admit
list could not be read or is invalid, or the files could not be written.

``agent-evidence-admission conformance run|replay|verify``: sign, replay and check conformance
result records; see ``conformance_cli``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, conformance_cli
from .coverage_check import (
    check,
    detect_format,
    format_report,
    parse_required,
)
from .digest_check import check as digest_check
from .digest_check import parse_document, read_source
from .generate import CLIENTS, generate, parse_admit_list
from .generate import format_report as format_generate_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-evidence-admission")
    parser.add_argument("--version", action="version", version=f"agent-evidence-admission {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    digest = commands.add_parser(
        "digest-check",
        help="check that an artifact has a digest its document (TEA, CycloneDX, in-toto) names",
    )
    digest.add_argument("document", help="path or https URL of the document that names the digest")
    digest.add_argument("artifact", help="path or https URL of the artifact the document covers")
    coverage = commands.add_parser(
        "coverage-check",
        help="check that a CycloneDX BOM or SPDX 3 document accounts for every class a buyer requires",
    )
    coverage.add_argument("document", help="path or https URL of the CycloneDX JSON BOM or SPDX 3 JSON-LD document")
    listing = coverage.add_mutually_exclusive_group(required=True)
    listing.add_argument("--required", help="path or https URL of the required-class list: a JSON array, a JSON object, or names")
    listing.add_argument("--require", help="the required classes inline, separated by commas")
    coverage.add_argument("--require-complete", action="store_true", help="fail a class stated incomplete as well")
    coverage.add_argument("--json", action="store_true", help="print the report as JSON")
    gen = commands.add_parser(
        "generate",
        help="render an admit list as the MCP allowlist each client enforces (Claude Code, Cursor, Windsurf, an MCP registry)",
    )
    gen.add_argument("admit_list", help="path or https URL of the admit list (JSON)")
    gen.add_argument("--out", required=True, help="directory to write the generated files into")
    gen.add_argument("--client", action="append", choices=CLIENTS, help="a client to generate for; repeat it; default every client")
    gen.add_argument("--json", action="store_true", help="print the report as JSON")
    conformance_cli.add_parsers(commands)
    return parser


def _run_digest(args: argparse.Namespace) -> int:
    try:
        document = parse_document(read_source(args.document))
        artifact = read_source(args.artifact)
    except (OSError, ValueError) as error:
        print(f"ERROR could not read: {error}", file=sys.stderr)
        return 2
    result = digest_check(document, artifact)
    if result.ok and result.matched:
        algorithm, value = result.matched
        print(f"PASS {args.artifact} has {algorithm}:{value}, named in {args.document}")
        return 0
    named = ", ".join(f"{a}:{v}" for a, v in result.declared) or "nothing"
    print(f"FAIL {result.reason}: {args.document} names {named}")
    return 1


def _run_coverage(args: argparse.Namespace) -> int:
    try:
        document = json.loads(read_source(args.document))
        text = args.require if args.require is not None else read_source(args.required).decode("utf-8")
        required = parse_required(text, detect_format(document))
        report = check(document, required, require_complete=args.require_complete)
    except (OSError, ValueError) as error:
        print(f"ERROR could not read: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report.as_dict(), indent=2) if args.json else format_report(report))
    return 0 if report.ok else 1


def _run_generate(args: argparse.Namespace) -> int:
    try:
        servers = parse_admit_list(json.loads(read_source(args.admit_list)))
    except (OSError, TypeError, ValueError) as error:
        print(f"ERROR could not read: {error}", file=sys.stderr)
        return 2
    result = generate(servers, tuple(dict.fromkeys(args.client or CLIENTS)))
    out = Path(args.out)
    try:
        for relative, text in result.files.items():
            path = out / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    except OSError as error:
        print(f"ERROR could not write: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.as_dict(), indent=2) if args.json else format_generate_report(result))
    return 0 if result.ok else 1


_COMMANDS = {
    "digest-check": _run_digest,
    "coverage-check": _run_coverage,
    "generate": _run_generate,
    "conformance": conformance_cli.run,
}


def main(argv: list[str] | None = None) -> int:
    words = list(sys.argv[1:] if argv is None else argv)
    tail: list[str] = []
    if "--" in words:  # the implementation command of "conformance run" follows the first "--"
        cut = words.index("--")
        words, tail = words[:cut], words[cut + 1 :]
    args = _parser().parse_args(words)
    if tail and args.command == "conformance":
        args.command_words = tail
    return _COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
