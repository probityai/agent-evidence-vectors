#!/usr/bin/env python3
"""``aee-bind``: build, sign, verify and regrade artifact-binding records.

    aee-bind keygen   --key <file>                    write an Ed25519 seed
    aee-bind build    <trial-dir> --verifier <dir> --key <file>
    aee-bind verify   <trial-dir> --pubkey <file>
    aee-bind regrade  <trial-dir> --verifier <dir> --key <file> --out <dir>
    aee-bind lineage  <record> [<record> ...]

Exit codes follow section 7 of ``spec/artifact-binding/v1.md``: 0 verified,
2 failed, 3 not-established, 1 a usage or environment error. A caller can
therefore tell "the bytes are wrong" from "the record does not reach a
conclusion" from "the tool could not run", which is the distinction the whole
contract exists to preserve.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import manifest as manifest_mod  # noqa: E402
import regrade as regrade_mod  # noqa: E402
import sign  # noqa: E402
import verify as verify_mod  # noqa: E402

BINDING_DIR = "binding"
MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"


def _paths(trial_dir: Path) -> tuple[Path, Path]:
    return (
        trial_dir / BINDING_DIR / MANIFEST_NAME,
        trial_dir / BINDING_DIR / SIGNATURE_NAME,
    )


def cmd_keygen(args: argparse.Namespace) -> int:
    seed = secrets.token_bytes(sign.SEED_LENGTH)
    key_path = Path(args.key)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(seed.hex(), encoding="utf-8")
    key_path.chmod(0o600)
    public = sign.public_bytes(seed)
    Path(args.pubkey or f"{args.key}.pub").write_text(public.hex(), encoding="utf-8")
    print(f"key_id {sign.key_id(public)}")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    trial_dir = Path(args.trial_dir)
    seed = sign.load_seed(Path(args.key) if args.key else None)
    public = sign.public_bytes(seed)
    facts = manifest_mod.collect_facts(trial_dir, Path(args.verifier) if args.verifier else None)
    record = manifest_mod.build(
        facts,
        operation="execute",
        verifier_id=args.verifier_id,
        signer_key_id=sign.key_id(public),
        recorded_at=args.recorded_at,
    )
    manifest_path, signature_path = _paths(trial_dir)
    raw = manifest_mod.write(record, manifest_path)
    signature_path.write_text(sign.sign_bytes(seed, raw).hex(), encoding="utf-8")
    print(f"wrote {manifest_path}")
    print(f"wrote {signature_path}")
    print(f"source_archive_digest {record['source_archive_digest']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    trial_dir = Path(args.trial_dir)
    manifest_path, signature_path = _paths(trial_dir)
    public = sign.load_public(Path(args.pubkey))
    in_force: dict[str, str] = {}
    for pin in args.in_force:
        role, sep, digest = pin.partition("=")
        if not sep or not role or len(digest) != 64:
            raise manifest_mod.BindingError(f"--in-force takes ROLE=SHA256, not {pin!r}")
        in_force[role] = digest
    if args.profile not in manifest_mod.PROFILES:
        raise manifest_mod.BindingError(
            f"unknown profile {args.profile!r}; known: {', '.join(sorted(manifest_mod.PROFILES))}"
        )
    outcome = verify_mod.verify(
        trial_dir, manifest_path, signature_path, public, args.profile, in_force
    )
    print(outcome.report())
    return outcome.exit_code


def cmd_regrade(args: argparse.Namespace) -> int:
    trial_dir = Path(args.trial_dir)
    manifest_path, signature_path = _paths(trial_dir)
    seed = sign.load_seed(Path(args.key) if args.key else None)
    public = sign.public_bytes(seed)
    try:
        outcome = regrade_mod.regrade(
            source_dir=trial_dir,
            source_manifest=manifest_path,
            source_signature=signature_path,
            public_key=public,
            private_seed=seed,
            verifier_dir=Path(args.verifier),
            target_dir=Path(args.out),
            verifier_id=args.verifier_id,
            recorded_at=args.recorded_at,
        )
    except regrade_mod.RegradeRefused as refusal:
        print(str(refusal))
        return verify_mod.EXIT_FAILED
    print(f"regraded into {outcome.trial_dir}")
    print(f"source_record_digest {outcome.source_digest}")
    print(f"reward {outcome.reward}")
    return 0


def cmd_lineage(args: argparse.Namespace) -> int:
    records = []
    digests = []
    for name in args.records:
        path = Path(name)
        record = verify_mod.read_record(path)
        if record is None:
            print(f"{path} is not a JSON object")
            return verify_mod.EXIT_USAGE
        records.append(record)
        digests.append(verify_mod.manifest_digest(path))
    problems = regrade_mod.check_lineage(records, digests)
    if problems:
        for problem in problems:
            print(f"  {problem}")
        return verify_mod.EXIT_FAILED
    print(f"lineage ok over {len(records)} record(s)")
    print(f"  one archive: {records[0]['source_archive_digest']}")
    for index, record in enumerate(records):
        graded = record.get("graded_outcome")
        reward = graded.get("reward") if isinstance(graded, dict) else None
        print(f"  record {index} ({record.get('operation')}): reward {reward}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aee-bind", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser("keygen", help="write an Ed25519 seed and public key")
    keygen.add_argument("--key", required=True)
    keygen.add_argument("--pubkey")
    keygen.set_defaults(handler=cmd_keygen)

    build = subparsers.add_parser("build", help="build and sign a record for a trial")
    build.add_argument("trial_dir")
    build.add_argument("--verifier")
    build.add_argument("--verifier-id", default="unknown")
    build.add_argument("--key")
    build.add_argument("--recorded-at")
    build.set_defaults(handler=cmd_build)

    check = subparsers.add_parser("verify", help="check a record against bytes on disk")
    check.add_argument("trial_dir")
    check.add_argument("--pubkey", required=True)
    check.add_argument("--profile", default=manifest_mod.PROFILE_NAME)
    check.add_argument(
        "--in-force",
        action="append",
        default=[],
        metavar="ROLE=SHA256",
        help="a digest the consumer holds as in force for ROLE; repeatable",
    )
    check.set_defaults(handler=cmd_verify)

    again = subparsers.add_parser("regrade", help="regrade a bound archive")
    again.add_argument("trial_dir")
    again.add_argument("--verifier", required=True)
    again.add_argument("--verifier-id", default="unknown")
    again.add_argument("--key")
    again.add_argument("--out", required=True)
    again.add_argument("--recorded-at")
    again.set_defaults(handler=cmd_regrade)

    lineage = subparsers.add_parser("lineage", help="check a chain of records")
    lineage.add_argument("records", nargs="+")
    lineage.set_defaults(handler=cmd_lineage)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = args.handler
    try:
        return int(handler(args))
    except (manifest_mod.BindingError, sign.KeyError_) as problem:
        print(f"aee-bind: {problem}")
        return verify_mod.EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
