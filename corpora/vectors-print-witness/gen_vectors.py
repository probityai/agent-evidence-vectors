"""Build the print-witness cases byte-identically.

A print witness sits between the agent that controls a machine and the machine
itself. It signs the job it received before forwarding it, then signs log
records while the job runs, and signs a closing record when the job ends. Every
case here is one such job: the G-code file the witness forwarded, the signed
log, and the consumer's trust inputs in ``case.json`` (the witness keys it
trusts and the digest of the G-code it ordered).

The cases ask the three questions a verifier of a signed machine record must
answer and a signature check alone does not: what it does when the log stops
early, when the G-code changed after the witness signed it, and when the log
is signed by a different witness than the one that saw the G-code.

Keys are Ed25519 seeds derived from published labels, so anyone can rebuild
every signature. They are test keys and protect nothing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402

SUITE = "print-witness/v1"
SEED_PREFIX = "agent-evidence-vectors/print-witness/v1/"
GENESIS = "0" * 64
TRUSTED = ("witness-a", "witness-b")
JOB, OTHER_JOB = "job-0001", "job-0002"
LAYERS = 5
START = "2026-11-16T09:00:00Z"


def _seed(label: str) -> bytes:
    return hashlib.sha256((SEED_PREFIX + label).encode()).digest()


def _public(label: str) -> str:
    """The public key of a labelled seed."""
    seed = _seed(label)
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return str(rail._pt_compress(rail._pt_mul(a, rail._B)).hex())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def gcode(infill: int = 15, label: str = "bracket") -> bytes:
    """A short G-code job: five layers of a test part, header comments first."""
    lines = [
        f"; print-witness/v1 test job: {label}",
        "; printer_model = Bambu Lab H2D",
        f"; total_layer_count = {LAYERS}",
        f"; sparse_infill_density = {infill}%",
        "; filament_type = PLA",
        "M140 S65 ; bed temperature",
        "M104 S220 ; nozzle temperature",
        "G28 ; home all axes",
        "G90",
        "M83",
    ]
    for layer in range(LAYERS):
        z = 0.2 * (layer + 1)
        lines += [
            f";LAYER_CHANGE {layer + 1} of {LAYERS}",
            f"G1 Z{z:.1f} F600",
            "G1 X40 Y40 F6000",
            "G1 X80 Y40 E2.1 F1800",
            "G1 X80 Y80 E2.1",
            "G1 X40 Y80 E2.1",
            "G1 X40 Y40 E2.1",
        ]
    lines += ["M104 S0", "M140 S0", "M84"]
    return ("\n".join(lines) + "\n").encode("ascii")


def _envelope(record: dict[str, Any], signer: str) -> bytes:
    """A log line: the record, the key identifier, and the signature over the
    record's RFC 8785 form by ``signer``'s key."""
    sig = rail.ed25519_sign(_seed(signer), rail.jcs_dumps(record))
    envelope = {"kid": record["witness"], "record": record,
                "sig": base64.b64encode(sig).decode()}
    return bytes(rail.jcs_dumps(envelope))


def _at(minutes: int) -> str:
    return f"2026-11-16T09:{minutes:02d}:00Z"


def records(job: str, job_bytes: bytes, witness: str, upto: int = LAYERS,
            close: str | None = "finished") -> list[dict[str, Any]]:
    """The unsigned records of one witnessed job, without their links.

    ``upto`` is the last layer logged; ``close`` is the status the closing
    record states, or None for a log with no closing record.
    """
    out: list[dict[str, Any]] = [{
        "at": START, "gcode_bytes": len(job_bytes), "gcode_sha256": _sha(job_bytes),
        "job": job, "layers": LAYERS, "type": "intake", "witness": witness}]
    for layer in range(1, upto + 1):
        out.append({"at": _at(10 * layer), "bed_c": 65, "job": job, "layer": layer,
                    "nozzle_c": 220, "type": "progress", "witness": witness})
    if close is not None:
        out.append({"at": _at(10 * upto + 5), "job": job, "layers_printed": upto,
                    "status": close, "type": "close", "witness": witness})
    return out


def link(unlinked: list[dict[str, Any]], signers: list[str] | None = None) -> list[bytes]:
    """Number and chain the records, each naming the digest of the line before
    it, and sign each with its witness key (or the signer named for it)."""
    lines: list[bytes] = []
    for i, record in enumerate(unlinked):
        body = {**record, "prev": _sha(lines[-1]) if lines else GENESIS, "seq": i}
        lines.append(_envelope(body, signers[i] if signers else record["witness"]))
    return lines


def _edited_without_key(line: bytes, **changes: Any) -> bytes:
    """Change fields of a signed record and keep its old signature, as an
    editor without the witness key must."""
    envelope = json.loads(line)
    envelope["record"].update(changes)
    return bytes(rail.jcs_dumps(envelope))


Case = tuple[str, bytes, list[bytes], str, str, str, str]


def cases() -> list[Case]:
    """Every case: id, G-code bytes, log lines, expected decision and reason,
    the accept case it pairs with, and what it changes."""
    job = gcode()
    altered = gcode(infill=10)
    other = gcode(label="hinge")
    intact = link(records(JOB, job, "witness-a"))
    by_b = link(records(JOB, job, "witness-b"))
    # Witness b signs the progress and close records of the job witness a took in.
    mixed = link([{**r, "witness": "witness-b"} if r["type"] != "intake" else r
                  for r in records(JOB, job, "witness-a")])
    stranger = link([{**r, "witness": "witness-c"} for r in records(JOB, job, "witness-a")])
    # Layers 3 to 5 and the close come from a second job the same witness ran.
    second = records(OTHER_JOB, other, "witness-a")
    spliced = link(records(JOB, job, "witness-a")[:3] + second[3:])
    reordered = intact[:2] + [intact[3], intact[2]] + intact[4:]
    edited = intact[:3] + [_edited_without_key(intact[3], nozzle_c=195)] + intact[4:]
    return [
        ("intact", job, intact, "verified", "print_witnessed", "",
         "control: one witness takes in the ordered G-code, logs every layer and closes"),
        ("intact-other-witness", job, by_b, "verified", "print_witnessed", "",
         "control: the same job witnessed end to end by the second trusted witness"),
        ("log-stops-early", job, intact[:4], "rejected", "log_truncated", "intact",
         "the log is cut after layer 3: no closing record, every signature verifies"),
        ("log-closes-early", job, link(records(JOB, job, "witness-a", 3, "aborted")),
         "rejected", "print_not_finished", "intact",
         "the witness signed a closing record that says the print stopped at layer 3"),
        ("gcode-changed-after-signing", altered, intact, "rejected", "gcode_altered", "intact",
         "the G-code beside the log is not the file the witness signed: infill 10% not 15%"),
        ("gcode-not-ordered", other, link(records(JOB, other, "witness-a")),
         "rejected", "gcode_not_ordered", "intact",
         "the witness took in and printed a different job from the one the consumer ordered"),
        ("witness-changed-mid-print", job, mixed, "rejected", "witness_changed",
         "intact-other-witness",
         "witness a took in the G-code and witness b signed the log: both keys are trusted "
         "and every signature verifies"),
        ("untrusted-witness", job, stranger, "rejected", "signature_invalid",
         "intact-other-witness",
         "the whole log is signed by a witness the consumer does not trust"),
        ("log-record-edited", job, edited, "rejected", "signature_invalid", "intact",
         "the nozzle temperature of layer 3 edited after signing, old signature kept"),
        ("log-from-other-print", job, spliced, "rejected", "job_mismatch", "intact",
         "layers 3 to 5 and the close come from another job the same witness ran, "
         "relinked: every signature and every link verifies"),
        ("log-reordered", job, reordered, "rejected", "chain_link_broken", "intact",
         "the records of layers 2 and 3 swapped: every signature verifies"),
        ("log-without-intake", job, intact[1:], "rejected", "intake_missing", "intact",
         "the intake record removed: the log never says which G-code the witness saw"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def _log_signatures_verify(lines: list[bytes], keys: dict[str, str]) -> bool:
    """Whether every log record verifies under the trusted key its kid names."""
    for line in lines:
        envelope = json.loads(line)
        key = keys.get(envelope["kid"])
        sig = base64.b64decode(envelope["sig"])
        if key is None or not rail.ed25519_verify(
                bytes.fromhex(key), rail.jcs_dumps(envelope["record"]), sig):
            return False
    return True


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    keys = {label: _public(label) for label in TRUSTED}
    ordered = _sha(gcode())
    entries = []
    for name, job_bytes, lines, decision, reason, pair, change in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        case = {"job": "job.gcode", "log": "log.jsonl",
                "order": {"gcode_sha256": ordered},
                "schema_version": "print-witness-case/v1", "witnesses": keys}
        files = {"case.json": _json(case), "job.gcode": job_bytes,
                 "log.jsonl": b"".join(line + b"\n" for line in lines)}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entry: dict[str, Any] = {
            "change": change, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "logSignaturesVerify": _log_signatures_verify(lines, keys),
            "path": f"cases/{name}",
        }
        if pair:
            entry["pairsWith"] = pair
        entries.append(entry)
    manifest = {
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier case.json --json; exit 0 verified, 1 rejected",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
