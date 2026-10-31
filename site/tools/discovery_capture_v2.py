#!/usr/bin/env python3
"""Check private receiver records against an exact retained journal prefix.

The reader validates the closed schema and re-derives all original range,
response and source bindings. It never executes retained command metadata or
scores discovery acceptance. Native answers and supplied metadata have distinct
origins. Unobserved retained bytes do not acquire a receiver timestamp.

export-public writes a new allowlisted summary. Native events, prompt, answer
text, argv, paths, original metadata, errors and private preferences stay private.
Optional page copies require --approval-manifest and --page-root. The closed
manifest has schema_version, reviewed=true and pages; each page selects path,
sha256, bytes, a credential-free HTTPS url and an output_name. Approval applies
to those exact reviewed bytes. Export performs no network or publication.
"""

from __future__ import annotations

import argparse
from itertools import islice
import os
from pathlib import Path
import sys

from jsonschema import Draft202012Validator

import discovery_capture_journal as custody

SCHEMA = Path(__file__).resolve().parents[1] / "data/discovery-capture-v2.schema.json"


def schema():
    value = custody.strict_json(custody.read_small(SCHEMA))
    Draft202012Validator.check_schema(value)
    return value


def metadata_result(path):
    binding = custody.file_binding(path)
    source_directory = Path(path).parent / "contract-source"
    custody.require(not source_directory.is_symlink(), "contract source directory is a symlink")
    sources = {name: custody.file_binding(source_directory / name) for name in ("discovery_capture_v2.py", "discovery-capture-v2.schema.json")}
    result = {"origin": "supplied_metadata", "metadata": binding, "selection": None,
              "state": "invalid", "refusal": None, "refusal_detail": None, "validator_sources": sources}
    if binding["bytes"] > custody.JSON_LIMIT:
        return {**result, "refusal": "metadata_oversized", "refusal_detail": "Metadata exceeds the parsing budget; original bytes remain retained."}
    try:
        selection = custody.strict_json(custody.read_small(path))
    except (ValueError, UnicodeError, RecursionError) as error:
        return {**result, "refusal": "invalid_json", "refusal_detail": str(error)[:16000]}
    error = next(Draft202012Validator(schema()["$defs"]["selection"]).iter_errors(selection), None)
    if error is not None:
        # ValidationError.__str__ renders the whole rejected instance. Slicing
        # that string afterwards still allocates it. Keep diagnostics bounded;
        # the original metadata already retains every rejected value.
        location = "/".join(str(part)[:120] for part in islice(error.absolute_path, 16))
        detail = f"Selection violates {str(error.validator)[:120]} at /{location}."
        return {**result, "refusal": "invalid_contract", "refusal_detail": detail}
    return {**result, "state": "valid", "selection": selection}


def retain_contract(directory, metadata):
    directory = Path(directory)
    with custody.attempt_lock(directory):
        rows, partial = custody.read_journal(directory)
        custody.require(not partial and not any(row["kind"] == "contract" for row in rows), "contract cannot replace an observation or append beyond a partial line")
        # Verify the existing prefix before extending it. Never mutate a bad prefix.
        custody.derive_record(directory)
        source_directory = directory / "contract-source"
        source_directory.mkdir(mode=0o700)
        for path in (Path(__file__), SCHEMA):
            custody.exclusive_write(source_directory / path.name, custody.read_small(path))
        destination = directory / "response-metadata.json"
        with custody.open_regular(metadata) as source, custody.open_regular(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL) as target:
            while chunk := source.read(65536):
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        custody.sync_directory(directory)
        journal = custody.Journal(directory, append=True)
        try:
            journal.append("contract", metadata_result(destination))
        finally:
            journal.close()
        record = custody.derive_record(directory)
        custody.write_projection(directory, directory / "record.json", record)
        return record


def check_record(record_path, directory):
    record = custody.strict_json(custody.read_small(record_path))
    # Derived records contain integer counters only. JSON Schema regards 1.0 as
    # an integer; the exact receiver representation must not silently accept it.
    def no_floats(value):
        custody.require(not isinstance(value, float), "receiver record must not contain float counters")
        if isinstance(value, dict):
            for item in value.values():
                no_floats(item)
        elif isinstance(value, list):
            for item in value:
                no_floats(item)
    no_floats(record)
    error = next(Draft202012Validator(schema()).iter_errors(record), None)
    custody.require(error is None, "receiver record schema differs")
    with custody.attempt_lock(directory, shared=True):
        expected = custody.derive_record(directory, record["sources"]["journal"])
    custody.require(record == expected, "record differs from retained original evidence")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "export-public"))
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--attempt-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--approval-manifest", type=Path)
    parser.add_argument("--page-root", type=Path)
    args = parser.parse_args(argv)
    try:
        record = check_record(args.record, args.attempt_dir)
        if args.operation == "export-public":
            custody.require(args.output is not None, "export-public requires a new output")
            from discovery_capture_recovery import export_public
            export_public(record, args.output, args.approval_manifest, args.page_root)
            return 0
        custody.require(args.output is None and args.approval_manifest is None and args.page_root is None,
                        "check does not export files")
        print(custody.canonical({"schema_version": 2, "response_state": record["response"]["state"],
                                "contract_state": record["contract"]["state"], "native_closure": record["native_closure"]["state"],
                                "driver_closure": record["driver_closure"]["state"]}).decode(), end="")
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
