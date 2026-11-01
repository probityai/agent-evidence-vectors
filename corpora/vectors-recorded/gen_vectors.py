"""Build the recorded-set corpus: its synthetic cases, manifest and index.

    uv run python vectors-recorded/gen_vectors.py

Two kinds of member live here. A RECORDED member under ``sets/<name>/`` holds
bytes from one live run, placed byte for byte as their publisher released them,
with a ``SOURCE.json`` naming where, at which commit, and the digests the
publisher stated in public. Those bytes are not generated and cannot be; this
generator refuses to run unless the digest list on disk is the one SOURCE.json
pins and every publicly stated digest still matches. A SYNTHETIC member under
``cases/<id>/`` is generated here, one mutation away from an intact synthetic
set, so that a checker of recorded sets is forced to refuse each way a set can
stop matching its list. The manifest and index are functions of both.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))
from agent_evidence_vectors import auditrecord  # noqa: E402
from agent_evidence_vectors import recorded as reader  # noqa: E402

SUITE = reader.SUITE


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sums(files: dict[str, bytes]) -> bytes:
    return b"".join(f"{_sha(body)}  ./{path}\n".encode() for path, body in sorted(files.items()))


def _ots(subject: bytes) -> bytes:
    """A proof file whose header commits to ``subject``; its tail is filler."""
    tail = bytes.fromhex(_sha(b"synthetic ots tail"))[:16]
    magic: bytes = reader.OTS_MAGIC
    return (magic + bytes([reader.OTS_VERSION, reader.OTS_SHA256])
            + bytes.fromhex(_sha(subject)) + b"\xf0\x10" + tail + b"\x00")


CHECKPOINT = b'{"head":"' + _sha(b"entry 1").encode() + b'","size":2}'
BASE = {
    "log/entries.jsonl": b'{"seq":0,"item":"budget"}\n{"seq":1,"item":"use"}\n',
    "log/checkpoint.json": CHECKPOINT,
    "log/checkpoint.stamp.ots": _ots(CHECKPOINT),
    "settlement.json": b'{"outcome":"synthetic"}',
}
BINDINGS = [{"type": reader.BINDING_OTS, "proof": "log/checkpoint.stamp.ots",
             "subject": "log/checkpoint.json"}]


# The anchored twin: a subject stating a time and a block it saw, an
# OpenTimestamps proof that runs to a Bitcoin attestation, and a synthetic
# header holding the commitment as its Merkle root. Its header time sits exactly
# the OpenTimestamps allowance before the stated time, so the twin is inside the
# allowance (the audit-record draft's R10) and one second more is outside it (R11).
STATED = 1792627866
HEIGHT = 900100
ALLOWANCE = reader.OTS_TOLERANCE_SECONDS


def _subject(stated: int, seen: int) -> bytes:
    return json.dumps({"as_of": stated, "seen_block": {"height": seen}},
                      sort_keys=True, separators=(",", ":")).encode()


def _anchored_proof(subject: bytes, nonce: bytes, pending: bool = False) -> tuple[bytes, bytes]:
    """A proof over ``subject`` (append a nonce, SHA-256, attest) and its commitment."""
    digest = hashlib.sha256(subject).digest()
    commitment = hashlib.sha256(digest + nonce).digest()
    if pending:
        tag, payload = auditrecord.OTS_PENDING, b"https://calendar.invalid"
    else:
        tag, payload = auditrecord.OTS_BITCOIN, _varuint(HEIGHT)
    body = (b"\xf0" + bytes([len(nonce)]) + nonce + b"\x08" + b"\x00" + tag
            + bytes([len(payload)]) + payload)
    magic: bytes = reader.OTS_MAGIC
    return magic + bytes([reader.OTS_VERSION, reader.OTS_SHA256]) + digest + body, commitment


def _varuint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _header(merkle_root: bytes, time: int) -> dict[str, Any]:
    header = ((0x20000000).to_bytes(4, "little") + bytes(32) + merkle_root
              + time.to_bytes(4, "little") + (0x1D00FFFF).to_bytes(4, "little") + bytes(4))
    return {"height": HEIGHT, "header": header.hex(), "id": reader.block_id(header)}


def _anchored(stated: int, seen: int, nonce: bytes, pending: bool = False
              ) -> tuple[dict[str, bytes], bytes]:
    subject = _subject(stated, seen)
    proof, commitment = _anchored_proof(subject, nonce, pending)
    return {"log/checkpoint.json": subject, "log/checkpoint.stamp.ots": proof}, commitment


def _anchor_binding(block: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"type": reader.BINDING_BTC, "proof": "log/checkpoint.stamp.ots",
             "subject": "log/checkpoint.json", "block": block,
             "after": "/seen_block/height", "statedTime": "/as_of"}]


def _anchored_cases() -> list[tuple[str, str, dict[str, bytes], str, list[dict[str, Any]]]]:
    """(slug, what it breaks, files, pin, bindings) for the anchored twin and its cases."""
    nonce = bytes.fromhex(_sha(b"anchored twin nonce"))[:8]
    files, commitment = _anchored(STATED, HEIGHT - 1, nonce)
    held = _header(commitment, STATED - ALLOWANCE)
    cases = [("anchor-intact", "nothing: the anchored twin, its stated time exactly the "
              "allowance after its header time", files, held)]
    late, late_root = _anchored(STATED + 1, HEIGHT - 1, nonce)
    cases.append(("stated-after-anchor", "the stated time one second past the allowance",
                  late, _header(late_root, STATED - ALLOWANCE)))
    seen, seen_root = _anchored(STATED, HEIGHT, nonce)
    cases.append(("anchor-not-after-seen", "the block the subject saw is the anchoring block",
                  seen, _header(seen_root, STATED - ALLOWANCE)))
    other, _ = _anchored(STATED, HEIGHT - 1, bytes.fromhex(_sha(b"other nonce"))[:8])
    cases.append(("anchor-mismatch", "the proof's path changed, the held header left alone",
                  other, held))
    pending, _ = _anchored(STATED, HEIGHT - 1, nonce, pending=True)
    cases.append(("anchor-pending", "the Bitcoin attestation replaced by a pending one",
                  pending, held))
    out = []
    for slug, what, body, block in cases:
        sums = _sums(body)
        out.append((slug, what, _set(body, sums), _sha(sums), _anchor_binding(block)))
    return out


ANCHORED_CODES = {"anchor-intact": [], "anchor-pending": ["anchor-mismatch"]}


def _set(files: dict[str, bytes], sums: bytes | None) -> dict[str, bytes]:
    out = dict(files)
    if sums is not None:
        out[reader.SUMS] = sums
    return out


def _cases() -> list[tuple[str, str, dict[str, bytes], str | None]]:
    """(slug, what it breaks, files, pin) for every synthetic member."""
    intact = _set(BASE, _sums(BASE))
    pin = _sha(intact[reader.SUMS])
    edited = {**BASE, "log/entries.jsonl": BASE["log/entries.jsonl"].replace(b"use", b"usf")}
    bad_ots = {**BASE, "log/checkpoint.stamp.ots": _ots(b"other bytes")}
    bad_magic = {**BASE, "log/checkpoint.stamp.ots": b"\x00NotTimestamps" + BASE[
        "log/checkpoint.stamp.ots"][14:]}
    one_space = _sums(BASE).replace(b"  ./settlement.json", b" settlement.json")
    escape = _sums(BASE) + f"{_sha(b'outside')}  ../outside.txt\n".encode()
    no_newline = _sums(BASE)[:-1]
    missing = {k: v for k, v in BASE.items() if k != "settlement.json"}
    cases: list[tuple[str, str, dict[str, bytes], str | None]] = [
        ("intact", "nothing: the twin every other case is one mutation from", intact, pin),
        ("digest-mismatch", "one listed file edited, its list left alone",
         _set(edited, _sums(BASE)), pin),
        ("file-missing", "one listed file removed", _set(missing, _sums(BASE)), pin),
        ("file-unlisted", "one file added that the list does not name",
         _set({**BASE, "notes.txt": b"added later\n"}, _sums(BASE)), pin),
        ("sums-unpinned", "a file edited and its list rewritten to match",
         _set(edited, _sums(edited)), pin),
        ("sums-missing", "the list removed", _set(BASE, None), pin),
    ]
    for slug, what, sums in (
        ("sums-malformed", "one line with a single space and no mode character", one_space),
        ("sums-unterminated", "the last line without its newline", no_newline),
        ("path-unsafe", "a line naming a path outside the set", escape),
    ):
        cases.append((slug, what, _set(BASE, sums), _sha(sums)))
    for slug, what, files in (
        ("binding-mismatch", "the timestamp proof commits to other bytes", bad_ots),
        ("binding-malformed", "the timestamp proof header does not parse", bad_magic),
    ):
        sums = _sums(files)
        cases.append((slug, what, _set(files, sums), _sha(sums)))
    return cases


def _tree_id(files: dict[str, bytes]) -> str:
    listing = {path: _sha(body) for path, body in sorted(files.items())}
    return "v" + _sha(reader.compact(listing))[:16]


def _write(directory: Path, files: dict[str, bytes]) -> None:
    for path, body in files.items():
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)


def _header_view(view: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """The held headers by height, refused unless each links to the one before."""
    path = ROOT / "sets" / view["member"] / "bytes" / view["file"]
    rows = reader._pointer(json.loads(path.read_bytes()), view["pointer"])
    held: dict[int, dict[str, Any]] = {}
    previous = None
    for row in rows:
        header = bytes.fromhex(row["hex"])
        if len(header) != 80 or (previous is not None and header[4:36][::-1].hex() != previous):
            raise SystemExit(f"{path}: the header view does not link at height {row['height']}")
        previous = reader.block_id(header)
        held[row["height"]] = {"height": row["height"], "header": row["hex"], "id": previous}
    return held


def _bindings(source: dict[str, Any]) -> list[dict[str, Any]]:
    """The declared bindings, each anchor given the header the view holds for it."""
    out = []
    view = _header_view(source["headerView"]) if "headerView" in source else {}
    for declared in source["bindings"]:
        binding = dict(declared)
        if binding["type"] == reader.BINDING_BTC:
            height = binding.pop("height")
            if height not in view:
                raise SystemExit(f"no header held for block {height}")
            binding["block"] = view[height]
        out.append(binding)
    return out


def _recorded_entries() -> list[dict[str, Any]]:
    entries = []
    for source_path in sorted((ROOT / "sets").glob("*/SOURCE.json")):
        source = json.loads(source_path.read_text(encoding="utf-8"))
        directory = source_path.parent / "bytes"
        rel = directory.relative_to(ROOT).as_posix()
        sums = (directory / reader.SUMS).read_bytes()
        if _sha(sums) != source["sumsSha256"]:
            raise SystemExit(f"{rel}/{reader.SUMS} is not the list SOURCE.json pins")
        for path, digest in source["publishedDigests"].items():
            if _sha((directory / path).read_bytes()) != digest:
                raise SystemExit(f"{rel}/{path} no longer has the digest its publisher stated")
        bindings = _bindings(source)
        codes = reader.check_set(directory, source["sumsSha256"], bindings)
        if codes:
            raise SystemExit(f"{rel} does not verify against its own list: {codes}")
        entries.append({
            "id": "v" + reader.tree_digest(directory)[:16], "name": source_path.parent.name,
            "kind": "recorded", "dir": rel, "file": f"{rel}/{reader.SUMS}",
            "sourceFile": source_path.relative_to(ROOT).as_posix(),
            "licenceFile": (source_path.parent / "LICENSE").relative_to(ROOT).as_posix(),
            "sumsSha256": source["sumsSha256"], "bindings": bindings,
            "expected": {"verdict": reader.VERIFIED, "codes": []},
            "source": {k: source[k] for k in ("repository", "commit", "path", "publishedIn",
                                              "contributor", "licence")},
        })
    return entries


def _synthetic_entries() -> list[dict[str, Any]]:
    shutil.rmtree(ROOT / "cases", ignore_errors=True)
    entries = []
    plain = [(slug, what, files, pin, BINDINGS) for slug, what, files, pin in _cases()]
    for slug, what, files, pin, bindings in plain + _anchored_cases():
        member_id = _tree_id(files)
        directory = ROOT / "cases" / member_id / "bytes"
        _write(directory, files)
        codes = reader.check_set(directory, pin, bindings)
        expected_codes = ANCHORED_CODES.get(slug, [] if slug == "intact" else [
            "sums-malformed" if slug == "sums-unterminated" else slug])
        if codes != expected_codes:
            raise SystemExit(f"{slug}: the reader answers {codes}, not {expected_codes}")
        rel = directory.relative_to(ROOT).as_posix()
        named = reader.SUMS if reader.SUMS in files else sorted(files)[0]
        sums_file = f"{rel}/{named}"
        entries.append({
            "id": member_id, "name": slug, "kind": "synthetic", "dir": rel, "file": sums_file,
            "sumsSha256": pin, "bindings": bindings, "breaks": what,
            "expected": {"verdict": reader.VERIFIED if not codes else reader.FAILED,
                         "codes": codes},
        })
    return entries


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """The digest the manifest states, recomputed from its vector rows."""
    return _sha(reader.compact(manifest["vectors"]))


def _index(entries: list[dict[str, Any]], digest: str) -> str:
    rows = [f"| `{e['id']}` | {e['kind']} | {e['name']} | {e['expected']['verdict']} | "
            f"{', '.join(f'`{c}`' for c in e['expected']['codes']) or '-'} |" for e in entries]
    return "\n".join([
        "# Recorded-set corpus index", "",
        "Generated by `gen_vectors.py` from the manifest; do not edit by hand.", "",
        f"Corpus digest: `{digest}`", "",
        "| id | kind | name | verdict | codes |", "| --- | --- | --- | --- | --- |",
        *rows, ""])


def main() -> int:
    entries = _recorded_entries() + _synthetic_entries()
    digest = _sha(reader.compact(entries))
    manifest = {
        "suite": SUITE,
        "contract": "vectors-recorded/README.md",
        "codes": list(reader.CODES),
        "corpusDigest": digest,
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["verdict"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (ROOT / "MANIFEST.json").write_bytes(reader.canonical(manifest))
    (ROOT / "INDEX.md").write_text(_index(entries, digest), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
