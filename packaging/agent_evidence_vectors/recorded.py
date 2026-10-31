"""Check recorded sets: retained bytes against the digest list their publisher wrote.

A recorded set is a directory of files from one live run, kept byte for byte
beside the ``SHA256SUMS`` file its publisher wrote. It is not the output of a
generator, so it cannot be regenerated; what can be checked is that the bytes are
still the bytes that were published. This reader checks exactly that, and the
check is narrow on purpose:

* the digest list is present (``sums-missing``) and well formed: one line per
  file, ``<64 lowercase hex><space><space or *><path>``, every line ending in a
  newline (``sums-malformed``);
* every path in it is relative, stays inside the set and appears once; a
  symbolic link inside the set is refused the same way (``path-unsafe``);
* every listed file is present (``file-missing``) and hashes to its listed
  digest (``digest-mismatch``);
* no file sits in the set that the list does not name (``file-unlisted``);
* the digest list itself is the one the manifest pins (``sums-unpinned``), so a
  file and its list edited together are still caught;
* each binding the manifest declares holds. ``opentimestamps-file-digest``
  says the OpenTimestamps proof file's own header commits to the SHA-256 of the
  named subject file (``binding-mismatch``), read from a header this reader can
  parse (``binding-malformed``); it reads nothing after the header.
  ``opentimestamps-bitcoin-header`` says the same and then runs every operation
  of the proof: one Bitcoin attestation at the held block's height must commit
  to the Merkle root of the 80-byte header the binding holds for that block,
  and the header must hash to the block id it is held under
  (``anchor-mismatch``). It may also name a JSON pointer into the subject for a
  block height the subject says it saw, which must be below the anchor
  (``anchor-not-after-seen``), and one for a Unix time the subject states,
  which must be no later than the header time plus 7200 seconds, the allowance
  draft-gilda-audit-agent-audit-record gives an OpenTimestamps time
  (``stated-after-anchor``). The header is a trust input: this reader does not
  check proof of work or that the block is on the chain with the most work.

A set that passes says the retained bytes match the digests that were published.
It says nothing about whether what those bytes record (a payment, a budget, a
settlement, a verdict) was right.

Two ways to run it::

    agent-evidence-vectors recorded                     # judge the shipped corpus
    agent-evidence-vectors recorded check DIR --member hs51-set2

The second checks a directory of your own, for example the set as its publisher
keeps it, against the digest list and bindings this corpus pins for a member, so
a publisher's CI can show its retained bytes have not moved since they were
recorded here. Exit 0 when verified, 1 when not, 2 when the check could not run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from .auditrecord import OTS_BITCOIN, _Reader, ots_attestations

SUITE = "recorded-set-conformance/v1"
SUMS = "SHA256SUMS"
VERIFIED, FAILED = "verified", "failed"
CODES = (
    "sums-missing",
    "sums-malformed",
    "path-unsafe",
    "file-missing",
    "digest-mismatch",
    "file-unlisted",
    "sums-unpinned",
    "binding-malformed",
    "binding-mismatch",
    "anchor-mismatch",
    "anchor-not-after-seen",
    "stated-after-anchor",
)
BINDING_OTS = "opentimestamps-file-digest"
BINDING_BTC = "opentimestamps-bitcoin-header"
#: The seconds a time stated beside an OpenTimestamps anchor may follow the
#: header time, the allowance the audit-record draft gives (its R10 and R11).
OTS_TOLERANCE_SECONDS = 7200
# The fixed header every OpenTimestamps proof file opens with, then a one-byte
# major version (1), then the file-hash operation tag (0x08 is SHA-256) and the
# digest of the stamped file. Nothing after that digest is read.
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_VERSION, OTS_SHA256 = 0x01, 0x08
_LINE = re.compile(rb"^([0-9a-f]{64}) [ *](.+)$")

_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-recorded" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-recorded")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    """The bytes the manifest is written as."""
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _unsafe(path: str) -> bool:
    parts = path.split("/")
    return (not path or path.startswith("/") or "\\" in path or path == SUMS
            or any(part in ("", ".", "..") for part in parts))


def parse_sums(data: bytes) -> tuple[dict[str, str] | None, set[str]]:
    """The listed path -> digest map, or None when the list does not parse."""
    if not data.endswith(b"\n"):
        return None, {"sums-malformed"}
    entries: dict[str, str] = {}
    codes: set[str] = set()
    for line in data[:-1].split(b"\n"):
        match = _LINE.match(line)
        if match is None:
            return None, {"sums-malformed"}
        try:
            path = match.group(2).decode("utf-8")
        except UnicodeDecodeError:
            return None, {"sums-malformed"}
        path = path[2:] if path.startswith("./") else path
        if _unsafe(path) or path in entries:
            codes.add("path-unsafe")
            continue
        entries[path] = match.group(1).decode("ascii")
    return entries, codes


def _present(directory: Path) -> tuple[set[str], bool]:
    """Every regular file under the set but the list, and whether a link was met."""
    found: set[str] = set()
    linked = False
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            linked = True
        elif path.is_file():
            rel = path.relative_to(directory).as_posix()
            if rel != SUMS:
                found.add(rel)
    return found, linked


def _ots_digest(proof: bytes) -> str | None:
    head = len(OTS_MAGIC)
    if (not proof.startswith(OTS_MAGIC) or len(proof) < head + 2 + 32
            or proof[head] != OTS_VERSION or proof[head + 1] != OTS_SHA256):
        return None
    return proof[head + 2:head + 34].hex()


def header_time(header: bytes) -> int:
    """The nTime field of an 80-byte Bitcoin block header."""
    return int.from_bytes(header[68:72], "little")


def block_id(header: bytes) -> str:
    """A block header's id as block explorers print it: SHA-256d, byte-reversed."""
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def _pointer(document: Any, pointer: str) -> Any:
    """The value at an RFC 6901 JSON pointer; KeyError when there is none."""
    if not pointer.startswith("/"):
        raise KeyError(pointer)
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(document, dict) and token in document:
            document = document[token]
        elif isinstance(document, list) and token.isdigit() and int(token) < len(document):
            document = document[int(token)]
        else:
            raise KeyError(pointer)
    return document


def _held_header(binding: dict[str, Any]) -> tuple[int, bytes] | None:
    block = binding.get("block")
    if not isinstance(block, dict) or type(block.get("height")) is not int:
        return None
    try:
        header = bytes.fromhex(str(block.get("header")))
    except ValueError:
        return None
    if len(header) != 80 or block_id(header) != block.get("id"):
        return None
    return block["height"], header


def _subject_integer(subject: bytes, pointer: str) -> int | None:
    try:
        value = _pointer(json.loads(subject), pointer)
    except (ValueError, KeyError):
        return None
    return value if type(value) is int else None


def _bitcoin_attestations(proof: bytes, subject: bytes) -> list[tuple[int, bytes]] | None:
    """Every (height, committed message) Bitcoin attestation; None when unreadable."""
    try:
        found = []
        for message, kind, payload in ots_attestations(proof, hashlib.sha256(subject).digest()):
            if kind == OTS_BITCOIN:
                reader = _Reader(payload)
                found.append((reader.varuint(), message))
                if reader.at != len(payload):
                    return None
    except ValueError:
        return None
    return found


def _anchor_codes(binding: dict[str, Any], proof: bytes, subject: bytes) -> set[str]:
    """What an opentimestamps-bitcoin-header binding adds to the header check."""
    held = _held_header(binding)
    heights = _bitcoin_attestations(proof, subject)
    if held is None or heights is None:
        return {"binding-malformed"}
    height, header = held
    codes: set[str] = set()
    if (height, header[36:68]) not in heights:
        codes.add("anchor-mismatch")
    for key, code in (("after", "anchor-not-after-seen"), ("statedTime", "stated-after-anchor")):
        if key not in binding:
            continue
        value = _subject_integer(subject, str(binding[key]))
        if value is None:
            return {"binding-malformed"}
        if key == "after" and value >= height:
            codes.add(code)
        if key == "statedTime" and value > header_time(header) + OTS_TOLERANCE_SECONDS:
            codes.add(code)
    return codes


def check_binding(directory: Path, binding: dict[str, Any], listed: dict[str, str]) -> set[str]:
    """The codes one declared binding draws; an empty set when it holds."""
    proof, subject = binding.get("proof"), binding.get("subject")
    if (binding.get("type") not in (BINDING_OTS, BINDING_BTC) or proof not in listed
            or subject not in listed or not (directory / str(proof)).is_file()
            or not (directory / str(subject)).is_file()):
        return {"binding-malformed"}
    proof_bytes = (directory / str(proof)).read_bytes()
    subject_bytes = (directory / str(subject)).read_bytes()
    committed = _ots_digest(proof_bytes)
    if committed is None:
        return {"binding-malformed"}
    if committed != sha256(subject_bytes):
        return {"binding-mismatch"}
    if binding["type"] == BINDING_BTC:
        return _anchor_codes(binding, proof_bytes, subject_bytes)
    return set()


def check_set(directory: Path, pin: str | None, bindings: list[dict[str, Any]]) -> list[str]:
    """Every code a recorded set draws, sorted; an empty list means verified."""
    sums_path = directory / SUMS
    if not sums_path.is_file() or sums_path.is_symlink():
        return ["sums-missing"]
    data = sums_path.read_bytes()
    codes: set[str] = set()
    if pin is not None and sha256(data) != pin:
        codes.add("sums-unpinned")
    listed, parse_codes = parse_sums(data)
    codes |= parse_codes
    if listed is None:
        return sorted(codes)
    present, linked = _present(directory)
    if linked:
        codes.add("path-unsafe")
    for path, digest in listed.items():
        if path not in present:
            codes.add("file-missing")
        elif sha256((directory / path).read_bytes()) != digest:
            codes.add("digest-mismatch")
    if present - set(listed):
        codes.add("file-unlisted")
    for binding in bindings:
        codes |= check_binding(directory, binding, listed)
    return sorted(codes)


def tree_digest(directory: Path) -> str:
    """The digest a member identifier is cut from: every file path and its digest."""
    files = {p.relative_to(directory).as_posix(): sha256(p.read_bytes())
             for p in sorted(directory.rglob("*")) if p.is_file()}
    return sha256(compact(files))


def compact(value: object) -> bytes:
    """The bytes the corpus digest and every member identifier are taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def load_manifest(root: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return manifest


def corpus_findings(root: Path, manifest: dict[str, Any]) -> list[str]:
    """Findings that belong to no single member."""
    entries = manifest.get("vectors", [])
    findings: list[str] = []
    if manifest.get("suite") != SUITE:
        findings.append(f"suite is {manifest.get('suite')!r}, not {SUITE!r}")
    if sha256(compact(entries)) != manifest.get("corpusDigest"):
        findings.append("corpusDigest does not recompute over the vectors")
    ids = [entry.get("id") for entry in entries]
    if not entries or len(set(ids)) != len(ids):
        findings.append("empty or duplicate member identifiers")
    declared = {entry.get("dir") for entry in entries}
    on_disk = {p.relative_to(root).as_posix() for p in root.glob("*/*/bytes") if p.is_dir()}
    for stray in sorted(on_disk - declared):
        findings.append(f"{stray} holds a set no manifest row names")
    return findings


def judge_member(root: Path, entry: dict[str, Any]) -> list[str]:
    """The member's findings: empty when it draws exactly its expected codes."""
    directory = root / str(entry.get("dir", ""))
    if not directory.is_dir():
        return [f"{entry.get('dir')} is not in the corpus"]
    if entry.get("id") != "v" + tree_digest(directory)[:16]:
        return ["identifier does not recompute over the member's bytes"]
    codes = check_set(directory, entry.get("sumsSha256"), entry.get("bindings", []))
    verdict = VERIFIED if not codes else FAILED
    expected = entry.get("expected", {})
    if verdict != expected.get("verdict") or codes != expected.get("codes"):
        return [f"expected {expected.get('verdict')} {expected.get('codes')}, "
                f"got {verdict} {codes}"]
    return []


def judge(root: Path = ROOT) -> tuple[int, list[str]]:
    """The number of members judged and every finding, corpus-level first."""
    try:
        manifest = load_manifest(root)
    except (OSError, ValueError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    errors = corpus_findings(root, manifest)
    answered = 0
    for entry in manifest.get("vectors", []):
        answered += 1
        errors.extend(f"{entry.get('id')}: {f}" for f in judge_member(root, entry))
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    if verifier is not None:
        print(f"the verifier {shlex.join(verifier)!r} did NOT run: {SUITE!r} is judged only by "
              "this package's own reader and has no external-verifier contract")
        return 2
    directory = Path(root)
    answered, errors = judge(directory)
    for error in errors:
        print(error)
    try:
        manifest = load_manifest(directory)
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    print(f"{SUITE}: own reader answered {answered} of {total} members, "
          f"{len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no member was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader",
        "verifier": {"command": None, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest.get("corpusDigest"),
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def _member(name: str) -> dict[str, Any] | None:
    for entry in load_manifest(ROOT).get("vectors", []):
        if name in (entry.get("id"), entry.get("name")):
            return dict(entry)
    return None


def _check_command(args: argparse.Namespace) -> int:
    directory = Path(args.dir)
    if not directory.is_dir():
        print(f"{args.dir} is not a directory, so nothing was checked")
        return 2
    pin, bindings = args.pin, []
    if args.member:
        entry = _member(args.member)
        if entry is None or entry.get("kind") != "recorded":
            print(f"no recorded member {args.member!r} in this corpus, so nothing was checked")
            return 2
        pin, bindings = entry["sumsSha256"], entry.get("bindings", [])
    codes = check_set(directory, pin, bindings)
    answer = {"verdict": VERIFIED if not codes else FAILED, "codes": codes,
              "pinned": pin is not None}
    print(json.dumps(answer, sort_keys=True) if args.json else
          f"{answer['verdict']} {' '.join(codes)}".rstrip())
    return 0 if not codes else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-evidence-vectors recorded",
        description=(__doc__ or SUITE).splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    one = sub.add_parser("check", help="check one directory against its digest list")
    one.add_argument("dir", help="the recorded set: a directory holding SHA256SUMS")
    one.add_argument("--member", help="pin the list and bindings of this corpus member")
    one.add_argument("--pin", help="the SHA-256 the digest list itself must have")
    one.add_argument("--json", action="store_true", help="print the answer as JSON")
    args = parser.parse_args(argv)
    if args.command == "check":
        return _check_command(args)
    answered, errors = judge(ROOT)
    for error in errors:
        print(error)
    total = len(load_manifest(ROOT).get("vectors", []))
    print(f"{SUITE}: answered {answered} of {total} members, {len(errors)} disagreements")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
