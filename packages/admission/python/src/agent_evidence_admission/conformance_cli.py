"""``agent-evidence-admission conformance``: run a corpus, replay posted runs, verify records.

``conformance run <manifest> ... -- <command ...>``: run the command once per case, write the signed
record (and optionally add it to a registry); exit 0 when the record was written.
``conformance replay <runs.json> ...``: sign one record per posted run row into a registry.
``conformance keygen|public-key``: make a signing seed, print the public key for one.
``conformance verify <record-or-registry> --trusted-key <hex>``: exit 0 when every record
verifies, 1 when any does not, 2 when something could not be read.

Every command exits 2 on a read or usage error, never 0 or 1, so a broken read is not a result.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from . import conformance_registry as registry
from . import conformance_result as cr
from . import dsse, ed25519


def add_parsers(commands: argparse._SubParsersAction) -> None:
    group = commands.add_parser("conformance", help="run a corpus and sign the result, replay posted runs, verify records")
    sub = group.add_subparsers(dest="conformance_command", required=True)
    run = sub.add_parser("run", help="run <command> <input> for every case in a manifest and sign the result")
    run.add_argument("manifest", help="JSON: {suite: {revision, commit}, cases: [{id, input, expect: accept|refuse}]}")
    run.add_argument("--implementation", required=True)
    run.add_argument("--run-label", required=True, choices=cr.RUN_LABELS)
    run.add_argument("--evidence", required=True, choices=cr.EVIDENCE)
    _signing(run)
    run.add_argument("--results-out", help="write the per-case verdicts here; they are the record's evidence")
    run.add_argument("--timeout", type=float, default=60.0, help="seconds per case")
    run.set_defaults(command_words=[])  # filled by cli.main from the words after "--"
    keygen = sub.add_parser("keygen", help="write a new signing seed to a file (mode 0600) and print the public key")
    keygen.add_argument("--seed-file", required=True, help="where to write the seed; an existing file is never overwritten")
    pub = sub.add_parser("public-key", help="print the public key for a seed file")
    pub.add_argument("--seed-file", required=True)
    replay = sub.add_parser("replay", help="sign one record per row of a posted-runs file (the vectors' docs/INDEPENDENT-RUNS.json)")
    replay.add_argument("runs", help="path of the posted-runs JSON")
    _signing(replay)
    verify = sub.add_parser("verify", help="verify one record file, or every record of a registry directory")
    verify.add_argument("path", help="a record (DSSE envelope) or a registry directory")
    verify.add_argument("--trusted-key", action="append", required=True, help="hex raw Ed25519 public key; repeat for more")
    verify.add_argument("--source", help="the evidence file whose canonical digest the record's subject must equal (one record only)")
    verify.add_argument("--json", action="store_true")


def _signing(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed-file", required=True, help="file holding the 32-byte signing seed as 64 hex characters")
    parser.add_argument("--registry", help="registry directory to add the record(s) to")
    parser.add_argument("--out", help="write the record (run only) to this file")


def _seed(path: str) -> bytes:
    text = Path(path).read_text(encoding="ascii").strip()
    seed = bytes.fromhex(text)
    if len(seed) != 32:
        raise ValueError("seed file must hold 64 hex characters")
    return seed


def _trusted(seed: bytes) -> dict[str, bytes]:
    public = ed25519.public_key(seed)
    return {dsse.keyid(public): public}


def _emit(envelope: dict, seed: bytes, args: argparse.Namespace) -> list[str]:
    lines = []
    if args.registry:
        root = Path(args.registry)
        entry = registry.add_record(root, envelope, _trusted(seed))
        lines.append(f"registered {entry['file']}")
    if getattr(args, "out", None):
        Path(args.out).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        lines.append(f"wrote {args.out}")
    return lines


def _run(args: argparse.Namespace) -> int:
    command = args.command_words
    if not command:
        print("ERROR no implementation command given after --", file=sys.stderr)
        return 2
    manifest_path = Path(args.manifest)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    seed = _seed(args.seed_file)
    results = cr.run_corpus(manifest, command, manifest_path.parent, args.timeout)
    statement = cr.statement_from_results(args.implementation, manifest, results, args.run_label, args.evidence)
    envelope = dsse.make_envelope(cr.canonical(statement), seed)
    if args.results_out:
        Path(args.results_out).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    score = statement["predicate"]["scores"][0]
    errored = sum(1 for r in results if r["verdict"] == "errored")
    for line in _emit(envelope, seed, args):
        print(line)
    print(f"{args.implementation} scored {score['passed']}/{score['total']} on suite revision {manifest['suite']['revision']} ({errored} errored)")
    return 0


def _keygen(args: argparse.Namespace) -> int:
    seed = secrets.token_bytes(32)
    descriptor = os.open(args.seed_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(seed.hex() + "\n")
    print(f"wrote {args.seed_file}")
    print(f"public key {ed25519.public_key(seed).hex()}")
    return 0


def _public_key(args: argparse.Namespace) -> int:
    print(ed25519.public_key(_seed(args.seed_file)).hex())
    return 0


def _replay(args: argparse.Namespace) -> int:
    runs = json.loads(Path(args.runs).read_text(encoding="utf-8"))
    seed = _seed(args.seed_file)
    count = 0
    for row in runs["runs"]:
        statement = cr.statement_from_row(runs["implementation"], row)
        envelope = dsse.make_envelope(cr.canonical(statement), seed)
        for line in _emit(envelope, seed, args):
            print(line)
        count += 1
    print(f"replayed {count} of {len(runs['runs'])} posted runs")
    return 0


def _verify(args: argparse.Namespace) -> int:
    trusted = {}
    for hex_key in args.trusted_key:
        public = bytes.fromhex(hex_key)
        trusted[dsse.keyid(public)] = public
    path = Path(args.path)
    if path.is_dir():
        findings = registry.verify_registry(path, trusted)
        checked = len(list((path / "records").glob("*.dsse.json"))) if (path / "records").is_dir() else 0
        if args.json:
            print(json.dumps({"ok": not findings and checked > 0, "checked": checked, "findings": findings}, indent=2))
        else:
            for finding in findings:
                print(f"FAIL {finding['file']}: {', '.join(finding['reasons'])}")
            print(f"{checked} records checked, {len(findings)} failing")
        return 0 if checked and not findings else 1
    source = json.loads(Path(args.source).read_text(encoding="utf-8")) if args.source else None
    verdict = cr.verify_record(json.loads(path.read_text(encoding="utf-8")), trusted, source)
    if args.json:
        print(json.dumps(verdict.as_dict(), indent=2))
    elif verdict.ok:
        print(f"PASS {path} ({verdict.implementation}, suite revision {verdict.revision}, key {verdict.keyid})")
    else:
        print(f"FAIL {path}: {', '.join(verdict.reasons)}")
    return 0 if verdict.ok else 1


_HANDLERS = {"run": _run, "replay": _replay, "verify": _verify, "keygen": _keygen, "public-key": _public_key}


def run(args: argparse.Namespace) -> int:
    """Dispatch a ``conformance`` subcommand; any read or value error exits 2."""
    try:
        return _HANDLERS[args.conformance_command](args)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR {type(error).__name__}: {error}", file=sys.stderr)
        return 2
